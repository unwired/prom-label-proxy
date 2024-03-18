// Copyright 2020 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package injectproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/efficientgo/core/merrors"
	"github.com/metalmatze/signal/server/signalhttp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

const (
	queryParam    = "query"
	matchersParam = "match[]"
)

type routes struct {
	upstream *url.URL
	handler  http.Handler
	el       ExtractLabeler

	mux            http.Handler
	modifiers      map[string]func(*http.Response) error
	errorOnReplace bool
	regexMatch     bool
}

type options struct {
	enableLabelAPIs    bool
	enableAlertsAPI    bool
	passthroughPaths   []string
	errorOnReplace     bool
	registerer         prometheus.Registerer
	regexMatch         bool
	pathPrefix         string
	modifyProxyRequest func(*http.Request)
}

type Option interface {
	apply(*options)
}

type optionFunc func(*options)

func (f optionFunc) apply(o *options) {
	f(o)
}

// WithPrometheusRegistry configures the proxy to use the given registerer.
func WithPrometheusRegistry(reg prometheus.Registerer) Option {
	return optionFunc(func(o *options) {
		o.registerer = reg
	})
}

// WithEnabledAlertsAPI enables proxying to Alerts API. If false, "501 Not implemented" will be return for those.
func WithEnabledAlertsAPI() Option {
	return optionFunc(func(o *options) {
		o.enableAlertsAPI = true
	})
}

// WithEnabledLabelsAPI enables proxying to labels API. If false, "501 Not implemented" will be return for those.
func WithEnabledLabelsAPI() Option {
	return optionFunc(func(o *options) {
		o.enableLabelAPIs = true
	})
}

// WithPassthroughPaths configures routes to register given paths as passthrough handlers for all HTTP methods.
// that, if requested, will be forwarded without enforcing label. Use with care.
// NOTE: Passthrough "all" paths like "/" or "" and regex are not allowed.
func WithPassthroughPaths(paths []string) Option {
	return optionFunc(func(o *options) {
		o.passthroughPaths = paths
	})
}

// WithErrorOnReplace causes the proxy to return 400 if a label matcher we want to
// inject is present in the query already and matches something different
func WithErrorOnReplace() Option {
	return optionFunc(func(o *options) {
		o.errorOnReplace = true
	})
}

// WithRegexMatch causes the proxy to handle tenant name as regexp
func WithRegexMatch() Option {
	return optionFunc(func(o *options) {
		o.regexMatch = true
	})
}

func WithPathPrefix(pathPrefix string) Option {
	return optionFunc(func(o *options) {
		o.pathPrefix = pathPrefix
	})
}

// WithModifyProxyRequest allows to modify the proxy request before it is sent to the upstream.
// can be used to add custom headers, like basic auth.
func WithModifyProxyRequest(f func(*http.Request)) Option {
	return optionFunc(func(o *options) {
		o.modifyProxyRequest = f
	})
}

// mux abstracts away the behavior we expect from the http.ServeMux type in this package.
type mux interface {
	http.Handler
	Handle(string, http.Handler)
}

// strictMux is a mux that wraps standard HTTP handler with safer handler that allows safe user provided handler registrations.
type strictMux struct {
	mux
	seen map[string]struct{}
}

func newStrictMux(m mux) *strictMux {
	return &strictMux{
		m,
		map[string]struct{}{},
	}

}

// Handle is like HTTP mux handle but it does not allow to register paths that are shared with previously registered paths.
// It also makes sure the trailing / is registered too.
// For example if /api/v1/federate was registered consequent registrations like /api/v1/federate/ or /api/v1/federate/some will
// return error. In the mean time request with both /api/v1/federate and /api/v1/federate/ will point to the handled passed by /api/v1/federate
// registration.
// This allows to de-risk ability for user to mis-configure and leak inject isolation.
func (s *strictMux) Handle(pattern string, handler http.Handler) error {
	sanitized := pattern
	for next := strings.TrimSuffix(sanitized, "/"); next != sanitized; sanitized = next {
	}

	if _, ok := s.seen[sanitized]; ok {
		return fmt.Errorf("pattern %q was already registered", sanitized)
	}

	for p := range s.seen {
		if strings.HasPrefix(sanitized+"/", p+"/") {
			return fmt.Errorf("pattern %q is registered, cannot register path %q that shares it", p, sanitized)
		}
	}

	s.mux.Handle(sanitized, handler)
	s.mux.Handle(sanitized+"/", handler)
	s.seen[sanitized] = struct{}{}

	return nil
}

// instrumentedMux wraps a mux and instruments it.
type instrumentedMux struct {
	mux
	i signalhttp.HandlerInstrumenter
}

func newInstrumentedMux(m mux, r prometheus.Registerer) *instrumentedMux {
	return &instrumentedMux{
		m,
		signalhttp.NewHandlerInstrumenter(r, []string{"handler"}),
	}
}

// Handle implements the mux interface.
func (i *instrumentedMux) Handle(pattern string, handler http.Handler) {
	i.mux.Handle(pattern, i.i.NewHandler(prometheus.Labels{"handler": pattern}, handler))
}

// ExtractLabeler is an HTTP handler that extract the label value to be
// enforced from the HTTP request.  If a valid label value is found, it should
// store it in the request's context.  Otherwise it should return an error in
// the HTTP response (usually 400 or 500).
type ExtractLabeler interface {
	ExtractLabel(next http.HandlerFunc) http.Handler
}

// HTTPFormEnforcer enforces a label value extracted from the HTTP form and query parameters.
type HTTPFormEnforcer struct {
	ParameterName string
	LabelName     string
}

// ExtractLabel implements the ExtractLabeler interface.
func (hff HTTPFormEnforcer) ExtractLabel(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		labelValues, err := hff.getLabelValues(r)
		if err != nil {
			prometheusAPIError(w, humanFriendlyErrorMessage(err), http.StatusBadRequest)
			return
		}

		// Remove the proxy label from the query parameters.
		q := r.URL.Query()
		q.Del(hff.ParameterName)
		r.URL.RawQuery = q.Encode()

		// Remove the param from the PostForm.
		if r.Method == http.MethodPost {
			if err := r.ParseForm(); err != nil {
				prometheusAPIError(w, fmt.Sprintf("Failed to parse the PostForm: %v", err), http.StatusInternalServerError)
				return
			}
			if r.PostForm.Get(hff.ParameterName) != "" {
				r.PostForm.Del(hff.ParameterName)
				newBody := r.PostForm.Encode()
				// We are replacing request body, close previous one (r.FormValue ensures it is read fully and not nil).
				_ = r.Body.Close()
				r.Body = io.NopCloser(strings.NewReader(newBody))
				r.ContentLength = int64(len(newBody))
			}
		}

		next.ServeHTTP(w, r.WithContext(WithLabelName(WithLabelValues(r.Context(), labelValues), hff.LabelName)))
	})
}

func (hff HTTPFormEnforcer) getLabelValues(r *http.Request) ([]string, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, fmt.Errorf("the form data can not be parsed: %w", err)
	}

	formValues := removeEmptyValues(r.Form[hff.ParameterName])
	if len(formValues) == 0 {
		return nil, fmt.Errorf("the %q query parameter must be provided", hff.ParameterName)
	}

	return formValues, nil
}

// HTTPHeaderEnforcer enforces a label value extracted from the HTTP headers.
type HTTPHeaderEnforcer struct {
	Name      string
	LabelName string
}

// ExtractLabel implements the ExtractLabeler interface.
func (hhe HTTPHeaderEnforcer) ExtractLabel(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		labelValues, err := hhe.getLabelValues(r)
		if err != nil {
			prometheusAPIError(w, humanFriendlyErrorMessage(err), http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r.WithContext(WithLabelName(WithLabelValues(r.Context(), labelValues), hhe.LabelName)))
	})
}

func (hhe HTTPHeaderEnforcer) getLabelValues(r *http.Request) ([]string, error) {
	headerValues := removeEmptyValues(r.Header[hhe.Name])

	if len(headerValues) == 0 {
		return nil, fmt.Errorf("missing HTTP header %q", hhe.Name)
	}

	return headerValues, nil
}

// StaticLabelEnforcer enforces a static label value.
type StaticLabelEnforcer struct {
	Values    []string
	LabelName string
}

// ExtractLabel implements the ExtractLabeler interface.
func (sle StaticLabelEnforcer) ExtractLabel(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next(w, r.WithContext(WithLabelName(WithLabelValues(r.Context(), sle.Values), sle.LabelName)))
	})
}

func NewRoutes(upstream *url.URL, extractLabeler ExtractLabeler, opts ...Option) (*routes, error) {
	opt := options{}
	for _, o := range opts {
		o.apply(&opt)
	}

	if opt.registerer == nil {
		opt.registerer = prometheus.NewRegistry()
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)

	if opt.modifyProxyRequest != nil {
		originalDirector := proxy.Director
		proxy.Director = func(r *http.Request) {
			opt.modifyProxyRequest(r)
			if opt.pathPrefix != "" {
				// compatibility with go1.22 removing the prefix from the path
				reg := regexp.MustCompile(strings.Replace(opt.pathPrefix, "{customer_id}", "([a-zA-Z0-9_-]+)", -1))
				r.URL.Path = reg.ReplaceAllString(r.URL.Path, "")
			}
			originalDirector(r)
		}
	}

	r := &routes{
		upstream:       upstream,
		handler:        proxy,
		el:             extractLabeler,
		errorOnReplace: opt.errorOnReplace,
		regexMatch:     opt.regexMatch,
	}
	mux := newStrictMux(newInstrumentedMux(http.NewServeMux(), opt.registerer))

	errs := merrors.New(
		mux.Handle(opt.pathPrefix+"/federate", r.el.ExtractLabel(enforceMethods(r.matcher, "GET"))),
		mux.Handle(opt.pathPrefix+"/api/v1/query", r.el.ExtractLabel(enforceMethods(r.query, "GET", "POST"))),
		mux.Handle(opt.pathPrefix+"/api/v1/query_range", r.el.ExtractLabel(enforceMethods(r.query, "GET", "POST"))),
		mux.Handle(opt.pathPrefix+"/api/v1/series", r.el.ExtractLabel(enforceMethods(r.matcher, "GET", "POST"))),
		mux.Handle(opt.pathPrefix+"/api/v1/query_exemplars", r.el.ExtractLabel(enforceMethods(r.query, "GET", "POST"))),
	)

	if opt.enableLabelAPIs {
		errs.Add(
			mux.Handle(opt.pathPrefix+"/api/v1/labels", r.el.ExtractLabel(enforceMethods(r.matcher, "GET", "POST"))),
			// Full path is /api/v1/label/<label_name>/values but http mux does not support patterns.
			// This is fine though as we don't care about name for matcher injector.
			mux.Handle(opt.pathPrefix+"/api/v1/label/", r.el.ExtractLabel(enforceMethods(r.matcher, "GET"))),
		)
	}

	if opt.enableAlertsAPI {
		errs.Add(
			mux.Handle(opt.pathPrefix+"/api/v1/alerts", r.el.ExtractLabel(enforceMethods(r.passthrough, "GET"))),
			mux.Handle(opt.pathPrefix+"/api/v1/rules", r.el.ExtractLabel(enforceMethods(r.passthrough, "GET"))),
			// Reject multi label values with assertSingleLabelValue() because the
			// semantics of the Silences API don't support multi-label matchers.
			mux.Handle(opt.pathPrefix+"/api/v2/silences", r.el.ExtractLabel(
				r.errorIfRegexpMatch(
					enforceMethods(
						assertSingleLabelValue(r.silences),
						"GET", "POST",
					),
				),
			)),
			mux.Handle(opt.pathPrefix+"/api/v2/silence/", r.el.ExtractLabel(
				r.errorIfRegexpMatch(
					enforceMethods(
						assertSingleLabelValue(r.deleteSilence),
						"DELETE",
					),
				),
			)),
			mux.Handle(opt.pathPrefix+"/api/v2/alerts/groups", r.el.ExtractLabel(enforceMethods(r.enforceFilterParameter, "GET"))),
			mux.Handle(opt.pathPrefix+"/api/v2/alerts", r.el.ExtractLabel(enforceMethods(r.alerts, "GET"))),
		)
	}

	errs.Add(
		mux.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		})),
	)

	if err := errs.Err(); err != nil {
		return nil, err
	}

	// Validate paths.
	for _, path := range opt.passthroughPaths {
		u, err := url.Parse(fmt.Sprintf("http://example.com%v", path))
		if err != nil {
			return nil, fmt.Errorf("path %q is not a valid URI path, got %v", path, opt.passthroughPaths)
		}
		if u.Path != path {
			return nil, fmt.Errorf("path %q is not a valid URI path, got %v", path, opt.passthroughPaths)
		}
		if u.Path == "" || u.Path == "/" {
			return nil, fmt.Errorf("path %q is not allowed, got %v", u.Path, opt.passthroughPaths)
		}
	}

	// Register optional passthrough paths.
	for _, path := range opt.passthroughPaths {
		if err := mux.Handle(opt.pathPrefix+path, http.HandlerFunc(r.passthrough)); err != nil {
			return nil, err
		}
	}

	r.mux = mux
	if opt.enableAlertsAPI {
		r.modifiers = map[string]func(*http.Response) error{
			opt.pathPrefix + "/api/v1/rules":  modifyAPIResponse(r.filterRules),
			opt.pathPrefix + "/api/v1/alerts": modifyAPIResponse(r.filterAlerts),
		}
	}

	proxy.ModifyResponse = r.ModifyResponse
	return r, nil
}

func (r *routes) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

func (r *routes) ModifyResponse(resp *http.Response) error {
	m, found := r.modifiers[resp.Request.URL.Path]
	if !found {
		// Return the server's response unmodified.
		return nil
	}
	return m(resp)
}

func enforceMethods(h http.HandlerFunc, methods ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		for _, m := range methods {
			if m == req.Method {
				h(w, req)
				return
			}
		}
		http.NotFound(w, req)
	}
}

func (r *routes) errorIfRegexpMatch(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if r.regexMatch {
			prometheusAPIError(w, "support for regex match not implemented", http.StatusNotImplemented)
			return
		}

		next(w, req)
	}
}

type ctxKey int

const (
	keyLabel ctxKey = iota
	keyLabelName
	keyLabelForceRegex
)

// MustLabelValues returns labels (previously stored using WithLabelValue())
// from the given context.
// It will panic if no label is found or the value is empty.
func MustLabelValues(ctx context.Context) []string {
	labels, ok := ctx.Value(keyLabel).([]string)
	if !ok {
		panic(fmt.Sprintf("can't find the %q value in the context", keyLabel))
	}
	if len(labels) == 0 {
		panic(fmt.Sprintf("empty %q value in the context", keyLabel))
	}

	sort.Strings(labels)

	return labels
}

// MustLabelValue returns the first (alphabetical order) label value previously
// stored using WithLabelValue() from the given context.
// Similar to MustLabelValues, it will panic if no label is found or the value
// is empty.
func MustLabelValue(ctx context.Context) string {
	v := MustLabelValues(ctx)
	return v[0]
}

// MustLabelName returns the label name previously stored using WithLabelName()
// If there was no label name stored, it will panic.
func MustLabelName(ctx context.Context) string {
	label, ok := ctx.Value(keyLabelName).(string)
	if !ok {
		panic(fmt.Sprintf("can't find the %q value in the context", keyLabelName))
	}
	if label == "" {
		panic(fmt.Sprintf("empty %q value in the context", keyLabelName))
	}

	return label
}

// MustLabelForceRegex returns the label force regex previously stored using WithForceRegexp()
func MustLabelForceRegex(ctx context.Context) bool {
	forceRegex, ok := ctx.Value(keyLabelForceRegex).(bool)
	if !ok {
		return false
	}
	return forceRegex
}

func labelValuesToRegexpString(labelValues []string, treatAsRegex bool) string {
	lvs := make([]string, len(labelValues))
	for i := range labelValues {
		if treatAsRegex {
			lvs[i] = labelValues[i]
		} else {
			lvs[i] = regexp.QuoteMeta(labelValues[i])
		}
	}

	return strings.Join(lvs, "|")
}

// WithForceRegexp stores if the label values should be treated as a regexp.
func WithForceRegexp(ctx context.Context) context.Context {
	return context.WithValue(ctx, keyLabelForceRegex, true)
}

// WithLabelName returns a new context with the given label name.
func WithLabelName(ctx context.Context, label string) context.Context {
	return context.WithValue(ctx, keyLabelName, label)
}

// WithLabelValues stores labels in the given context.
func WithLabelValues(ctx context.Context, labels []string) context.Context {
	return context.WithValue(ctx, keyLabel, labels)
}

func (r *routes) passthrough(w http.ResponseWriter, req *http.Request) {
	r.handler.ServeHTTP(w, req)
}

func (r *routes) query(w http.ResponseWriter, req *http.Request) {
	var matcher *labels.Matcher

	forceRegex := MustLabelForceRegex(req.Context())
	if len(MustLabelValues(req.Context())) > 1 {
		if r.regexMatch && !forceRegex {
			prometheusAPIError(w, "Only one label value allowed with regex match", http.StatusBadRequest)
			return
		}
		matcher = &labels.Matcher{
			Name:  MustLabelName(req.Context()),
			Type:  labels.MatchRegexp,
			Value: labelValuesToRegexpString(MustLabelValues(req.Context()), forceRegex),
		}
	} else {
		matcherType := labels.MatchEqual
		matcherValue := MustLabelValue(req.Context())
		if r.regexMatch {
			compiledRegex, err := regexp.Compile(matcherValue)
			if err != nil {
				prometheusAPIError(w, err.Error(), http.StatusBadRequest)
				return
			}
			if compiledRegex.MatchString("") {
				prometheusAPIError(w, "Regex should not match empty string", http.StatusBadRequest)
				return
			}
			matcherType = labels.MatchRegexp
		}
		if forceRegex {
			matcherType = labels.MatchRegexp
		}
		matcher = &labels.Matcher{
			Name:  MustLabelName(req.Context()),
			Type:  matcherType,
			Value: matcherValue,
		}
	}

	e := NewEnforcer(r.errorOnReplace, matcher)

	// The `query` can come in the URL query string and/or the POST body.
	// For this reason, we need to try to enforcing in both places.
	// Note: a POST request may include some values in the URL query string
	// and others in the body. If both locations include a `query`, then
	// enforce in both places.
	q, found1, err := enforceQueryValues(e, req.URL.Query())
	if err != nil {
		switch err.(type) {
		case IllegalLabelMatcherError:
			prometheusAPIError(w, err.Error(), http.StatusBadRequest)
		case queryParseError:
			prometheusAPIError(w, err.Error(), http.StatusBadRequest)
		case enforceLabelError:
			prometheusAPIError(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	req.URL.RawQuery = q

	var found2 bool
	// Enforce the query in the POST body if needed.
	if req.Method == http.MethodPost {
		if err := req.ParseForm(); err != nil {
			prometheusAPIError(w, err.Error(), http.StatusBadRequest)
		}
		q, found2, err = enforceQueryValues(e, req.PostForm)
		if err != nil {
			switch err.(type) {
			case IllegalLabelMatcherError:
				prometheusAPIError(w, err.Error(), http.StatusBadRequest)
			case queryParseError:
				prometheusAPIError(w, err.Error(), http.StatusBadRequest)
			case enforceLabelError:
				prometheusAPIError(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		// We are replacing request body, close previous one (ParseForm ensures it is read fully and not nil).
		_ = req.Body.Close()
		req.Body = io.NopCloser(strings.NewReader(q))
		req.ContentLength = int64(len(q))
	}

	// If no query was found, return early.
	if !found1 && !found2 {
		return
	}

	r.handler.ServeHTTP(w, req)
}

func enforceQueryValues(e *Enforcer, v url.Values) (values string, noQuery bool, err error) {
	// If no values were given or no query is present,
	// e.g. because the query came in the POST body
	// but the URL query string was passed, then finish early.
	if v.Get(queryParam) == "" {
		return v.Encode(), false, nil
	}
	expr, err := parser.ParseExpr(v.Get(queryParam))
	if err != nil {
		queryParseError := newQueryParseError(err)
		return "", true, queryParseError
	}

	if err := e.EnforceNode(expr); err != nil {
		if _, ok := err.(IllegalLabelMatcherError); ok {
			return "", true, err
		}
		enforceLabelError := newEnforceLabelError(err)
		return "", true, enforceLabelError
	}

	v.Set(queryParam, expr.String())
	return v.Encode(), true, nil
}

// matcher ensures all the provided match[] if any has label injected. If none was provided, single matcher is injected.
// This works for non-query Prometheus APIs like: /api/v1/series, /api/v1/label/<name>/values, /api/v1/labels and /federate support multiple matchers.
// See e.g https://prometheus.io/docs/prometheus/latest/querying/api/#querying-metadata
func (r *routes) matcher(w http.ResponseWriter, req *http.Request) {
	matcher := &labels.Matcher{
		Name:  MustLabelName(req.Context()),
		Type:  labels.MatchRegexp,
		Value: labelValuesToRegexpString(MustLabelValues(req.Context()), MustLabelForceRegex(req.Context())),
	}

	q := req.URL.Query()
	if err := injectMatcher(q, matcher); err != nil {
		return
	}

	req.URL.RawQuery = q.Encode()
	if req.Method == http.MethodPost {
		if err := req.ParseForm(); err != nil {
			return
		}

		q = req.PostForm
		if err := injectMatcher(q, matcher); err != nil {
			return
		}

		// We are replacing request body, close previous one (ParseForm ensures it is read fully and not nil).
		_ = req.Body.Close()
		newBody := q.Encode()
		req.Body = io.NopCloser(strings.NewReader(newBody))
		req.ContentLength = int64(len(newBody))
	}

	r.handler.ServeHTTP(w, req)
}

func injectMatcher(q url.Values, matcher *labels.Matcher) error {
	matchers := q[matchersParam]
	if len(matchers) == 0 {
		q.Set(matchersParam, matchersToString(matcher))
		return nil
	}

	// Inject label into existing matchers.
	for i, m := range matchers {
		ms, err := parser.ParseMetricSelector(m)
		if err != nil {
			return err
		}

		matchers[i] = matchersToString(append(ms, matcher)...)
	}
	q[matchersParam] = matchers

	return nil
}

func matchersToString(ms ...*labels.Matcher) string {
	var el []string
	for _, m := range ms {
		el = append(el, m.String())
	}
	return fmt.Sprintf("{%v}", strings.Join(el, ","))
}

type queryParseError struct {
	msg string
}

func (e queryParseError) Error() string {
	return e.msg
}

func newQueryParseError(err error) queryParseError {
	return queryParseError{msg: fmt.Sprintf("error parsing query string %q", err.Error())}
}

type enforceLabelError struct {
	msg string
}

func (e enforceLabelError) Error() string {
	return e.msg
}

func newEnforceLabelError(err error) enforceLabelError {
	return enforceLabelError{msg: fmt.Sprintf("error enforcing label %q", err.Error())}
}

// humanFriendlyErrorMessage returns an error message with a capitalized first letter
// and a punctuation at the end.
func humanFriendlyErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	errMsg := err.Error()
	return fmt.Sprintf("%s%s.", strings.ToUpper(errMsg[:1]), errMsg[1:])
}

func removeEmptyValues(slice []string) []string {
	for i := 0; i < len(slice); i++ {
		if slice[i] == "" {
			slice = append(slice[:i], slice[i+1:]...)
			i--
		}
	}

	return slice
}
