package grant

import (
	"fmt"
	"net/http"
	"net/url"
	"path"

	"k8s.io/klog"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"

	oapi "github.com/openshift/api/oauth/v1"
	oauthclient "github.com/openshift/client-go/oauth/clientset/versioned/typed/oauth/v1"
	scopemetadata "github.com/openshift/library-go/pkg/authorization/scopemetadata"
	"github.com/openshift/oauth-server/pkg"
	"github.com/openshift/oauth-server/pkg/api"
	"github.com/openshift/oauth-server/pkg/scopecovers"
	"github.com/openshift/oauth-server/pkg/server/csrf"
	"github.com/openshift/oauth-server/pkg/server/redirect"
)

const (
	thenParam        = "then"
	csrfParam        = "csrf"
	clientIDParam    = "client_id"
	userNameParam    = "user_name"
	scopeParam       = "scope"
	redirectURIParam = "redirect_uri"

	approveParam = "approve"
	denyParam    = "deny"
)

// FormRenderer is responsible for rendering a Form to prompt the user
// to approve or reject a requested OAuth scope grant.
type FormRenderer interface {
	Render(form Form, w http.ResponseWriter, req *http.Request)
}

type Form struct {
	Action string
	Error  string

	ServiceAccountName      string
	ServiceAccountNamespace string

	GrantedScopes interface{}

	Names  GrantFormFields
	Values GrantFormFields
}

type GrantFormFields struct {
	Then        string
	CSRF        string
	ClientID    string
	UserName    string
	Scopes      interface{}
	RedirectURI string
	Approve     string
	Deny        string
}

type Scope struct {
	// Name is the string included in the OAuth scope parameter
	Name string
	// Description is a human-readable description of the scope. May be empty.
	Description string
	// Warning is a human-readable warning about the scope. Typically used to scare the user about escalating permissions. May be empty.
	Warning string
	// Error is a human-readable error, typically around the validity of the scope. May be empty.
	Error string
	// Granted indicates whether the user has already granted this scope.
	Granted bool
}

type Grant struct {
	auth           authenticator.Request
	csrf           csrf.CSRF
	render         FormRenderer
	clientregistry api.OAuthClientGetter
	authregistry   oauthclient.OAuthClientAuthorizationInterface
}

func NewGrant(csrf csrf.CSRF, auth authenticator.Request, render FormRenderer, clientregistry api.OAuthClientGetter, authregistry oauthclient.OAuthClientAuthorizationInterface) *Grant {
	return &Grant{
		auth:           auth,
		csrf:           csrf,
		render:         render,
		clientregistry: clientregistry,
		authregistry:   authregistry,
	}
}

func (l *Grant) Install(mux oauthserver.Mux, prefix string) {
	mux.Handle(prefix, l)
}

func (l *Grant) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	authResponse, ok, err := l.auth.AuthenticateRequest(req)
	if err != nil || !ok {
		l.redirect("You must reauthenticate before continuing", w, req)
		return
	}
	switch req.Method {
	case "GET":
		l.handleForm(authResponse.User, w, req)
	case "POST":
		l.handleGrant(authResponse.User, w, req)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (l *Grant) handleForm(user user.Info, w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	then := q.Get(thenParam)
	clientID := q.Get(clientIDParam)
	scopes := scopecovers.Split(q.Get(scopeParam))
	redirectURI := q.Get(redirectURIParam)

	client, err := l.clientregistry.Get(clientID, metav1.GetOptions{})
	if err != nil || client == nil {
		l.failed("Could not find client for client_id", w, req)
		return
	}

	if err := scopemetadata.ValidateScopeRestrictions(client, scopes...); err != nil {
		failure := fmt.Sprintf("%v requested illegal scopes (%v): %v", client.Name, scopes, err)
		l.failed(failure, w, req)
		return
	}

	grantedScopeNames := []string{}
	grantedScopes := []Scope{}
	requestedScopes := []Scope{}

	clientAuthID := user.GetName() + ":" + client.Name
	if clientAuth, err := l.authregistry.Get(clientAuthID, metav1.GetOptions{}); err == nil {
		grantedScopeNames = clientAuth.Scopes
	}

	for _, s := range scopes {
		requestedScopes = append(requestedScopes, getScopeData(s, grantedScopeNames))
	}
	for _, s := range grantedScopeNames {
		grantedScopes = append(grantedScopes, getScopeData(s, grantedScopeNames))
	}

	// Submit to the current path, so we can target this page even via an auth proxy.
	// Depends on any auth proxies matching at least the last segment of the URL.
	_, lastSegment := path.Split(req.URL.Path)

	form := Form{
		Action:        lastSegment,
		GrantedScopes: grantedScopes,
		Names: GrantFormFields{
			Then:        thenParam,
			CSRF:        csrfParam,
			ClientID:    clientIDParam,
			UserName:    userNameParam,
			Scopes:      scopeParam,
			RedirectURI: redirectURIParam,
			Approve:     approveParam,
			Deny:        denyParam,
		},
		Values: GrantFormFields{
			Then:        then,
			CSRF:        l.csrf.Generate(w, req),
			ClientID:    client.Name,
			UserName:    user.GetName(),
			Scopes:      requestedScopes,
			RedirectURI: redirectURI,
		},
	}

	if saNamespace, saName, err := serviceaccount.SplitUsername(client.Name); err == nil {
		form.ServiceAccountName = saName
		form.ServiceAccountNamespace = saNamespace
	}

	l.render.Render(form, w, req)
}

func (l *Grant) handleGrant(user user.Info, w http.ResponseWriter, req *http.Request) {
	if ok := l.csrf.Check(req, req.PostFormValue(csrfParam)); !ok {
		klog.V(4).Infof("Invalid CSRF token: %s", req.PostFormValue(csrfParam))
		l.failed("Invalid CSRF token", w, req)
		return
	}

	req.ParseForm()
	then := req.PostFormValue(thenParam)
	scopes := scopecovers.Join(req.PostForm[scopeParam])
	username := req.PostFormValue(userNameParam)

	if username != user.GetName() {
		klog.Errorf("User (%v) did not match authenticated user (%v)", username, user.GetName())
		l.failed("User did not match", w, req)
		return
	}

	if len(req.PostFormValue(approveParam)) == 0 || len(scopes) == 0 {
		// Redirect with an error param
		url, err := url.Parse(then)
		if len(then) == 0 || err != nil {
			l.failed("Access denied, but no redirect URL was specified", w, req)
			return
		}
		q := url.Query()
		q.Set("error", "access_denied")
		url.RawQuery = q.Encode()
		w.Header().Set("Location", url.String())
		w.WriteHeader(http.StatusFound)
		return
	}

	clientID := req.PostFormValue(clientIDParam)
	client, err := l.clientregistry.Get(clientID, metav1.GetOptions{})
	if err != nil || client == nil {
		l.failed("Could not find client for client_id", w, req)
		return
	}
	if err := scopemetadata.ValidateScopeRestrictions(client, scopecovers.Split(scopes)...); err != nil {
		failure := fmt.Sprintf("%v requested illegal scopes (%v): %v", client.Name, scopes, err)
		l.failed(failure, w, req)
		return
	}

	clientAuthID := user.GetName() + ":" + client.Name

	clientAuth, err := l.authregistry.Get(clientAuthID, metav1.GetOptions{})
	if err == nil && clientAuth != nil {
		// Add new scopes and update
		clientAuth.Scopes = scopecovers.Add(clientAuth.Scopes, scopecovers.Split(scopes))
		if _, err = l.authregistry.Update(clientAuth); err != nil {
			klog.Errorf("Unable to update authorization: %v", err)
			l.failed("Could not update client authorization", w, req)
			return
		}
	} else {
		// Make sure client name, user name, grant scope, expiration, and redirect uri match
		clientAuth = &oapi.OAuthClientAuthorization{
			UserName:   user.GetName(),
			UserUID:    user.GetUID(),
			ClientName: client.Name,
			Scopes:     scopecovers.Split(scopes),
		}
		clientAuth.Name = clientAuthID

		if _, err = l.authregistry.Create(clientAuth); err != nil {
			klog.Errorf("Unable to create authorization: %v", err)
			l.failed("Could not create client authorization", w, req)
			return
		}
	}

	// Redirect, overriding the scope param on the redirect with the scopes that were actually granted
	url, err := url.Parse(then)
	if len(then) == 0 || err != nil {
		l.failed("Access granted, but no redirect URL was specified", w, req)
		return
	}
	q := url.Query()
	q.Set(scopeParam, scopes)
	url.RawQuery = q.Encode()
	w.Header().Set("Location", url.String())
	w.WriteHeader(http.StatusFound)
}

func (l *Grant) failed(reason string, w http.ResponseWriter, req *http.Request) {
	form := Form{
		Error: reason,
	}
	l.render.Render(form, w, req)
}
func (l *Grant) redirect(reason string, w http.ResponseWriter, req *http.Request) {
	then := req.FormValue(thenParam)

	if !redirect.IsServerRelativeURL(then) {
		l.failed(reason, w, req)
		return
	}

	w.Header().Set("Location", then)
	w.WriteHeader(http.StatusFound)
}

func getScopeData(scopeName string, grantedScopeNames []string) Scope {
	scopeData := Scope{
		Name:    scopeName,
		Error:   fmt.Sprintf("Unknown scope"),
		Granted: scopecovers.Covers(grantedScopeNames, []string{scopeName}),
	}
	for _, evaluator := range scopemetadata.ScopeDescribers {
		if !evaluator.Handles(scopeName) {
			continue
		}
		description, warning, err := evaluator.Describe(scopeName)
		scopeData.Description = description
		scopeData.Warning = warning
		if err == nil {
			scopeData.Error = ""
		} else {
			scopeData.Error = err.Error()
		}
		break
	}
	return scopeData
}

// DefaultFormRenderer displays a page prompting the user to approve an OAuth grant.
// The requesting client id, requested scopes, and redirect URI are displayed to the user.
var DefaultFormRenderer = grantTemplateRenderer{}

type grantTemplateRenderer struct{}

func (r grantTemplateRenderer) Render(form Form, w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	if err := defaultGrantTemplate.Execute(w, form); err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to render grant template: %v", err))
	}
}
