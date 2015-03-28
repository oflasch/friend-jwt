(ns friend-jwt.core
  (:require [ring.middleware.defaults :refer :all]
            [ring.util.request :as req]
            [compojure.core :refer :all]
            [compojure.route :as route]
            [cemerick.friend :as friend]
            [cemerick.friend.credentials :as creds]
            [cemerick.friend.workflows :as workflows]
            [cemerick.friend.util :refer [gets]]
            [clj-jwt.core :refer :all]
            [clj-jwt.key :refer [public-key private-key]]
            [clj-time.core :refer [now plus seconds minutes hours days months before? after?]]
            [clj-jwt.intdate :refer [intdate->joda-time]]
            [cheshire.core :as json]))

(def users {"friend" {:username "friend"
                      :password (creds/hash-bcrypt "clojure")
                      :roles #{::user}}
            "oflasch" {:username "oflasch"
                       :password (creds/hash-bcrypt "kaktus")
                       :roles #{::admin}}})

(derive ::admin ::user) ; admins are considered to be also users

(def jwt-service-config
  {:algorithm :HS256 ; FIXME use asymmetric encryption
   :private-key "theSecret" ; FIXME plain text secret in the source code says it all...
   :token-time-to-live (minutes 2)})

(def jwt-client-config
  {:algorithm :HS256 ; FIXME use asymmetric encryption
   :public-key "theSecret"}) ; FIXME plain text secret in the source code says it all...


;;; library code starts here...
;;; ---------------------------------------------------------------------------
(defn- make-token-string [claim service-config]
  (-> claim
      jwt
      (sign (service-config :algorithm) (service-config :private-key))
      to-str))

; TODO add support for the claims defined in https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
(defn- user-claim [user-record token-time-to-live]
  {:user-id (user-record :username)
   ;; strip the user record of its password and convert it to an edn string
   :user-record-string (str (dissoc user-record :password))
   ;; standard claims
   :exp (plus (now) token-time-to-live)
   :iat (now)})

(defn- verify-jwt-token [client-config jwt-token]
  (let [expiration (intdate->joda-time (get-in jwt-token [:claims :exp]))
        issued-at (intdate->joda-time (get-in jwt-token [:claims :iat]))
        current-time (now)]
    (and (verify jwt-token (client-config :public-key))
         (not (after? current-time expiration))
         (not (before? current-time issued-at))
         jwt-token)))

(defn- decode-and-verify-token-string [client-config token-string]
  (try
    (let [jwt-token (str->jwt token-string)]
      (verify-jwt-token client-config jwt-token))
    (catch Exception e
      nil)))

(defn- workflow-deny [& _]
  {:status 401 :headers {"Content-Type" "text/plain"}})

(defn- request->token-string [request token-header]
  ((:headers request) (.toLowerCase token-header)))

(defn- extend-token [{:keys [get-user-fn token-header client-config service-config] :as config} request]
  (when-let [token-string (request->token-string request token-header)]
    (when-let [token-user-record-string (get-in (decode-and-verify-token-string client-config token-string) [:claims :user-record-string])]
      (let [token-user-record (read-string token-user-record-string)
            token-user-name (:username token-user-record)]
        (when-let [user-record (get-user-fn token-user-name)]
          (let [token-time-to-live (service-config :token-time-to-live)
                token-string (make-token-string (user-claim user-record token-time-to-live) service-config)] ; create jwt token
            {:status 200 :headers {token-header token-string}}))))))

(defn- verify-token [{:keys [token-header client-config] :as config} request]
  (when-let [token-string (request->token-string request token-header)]
    (when-let [user-record-string (get-in (decode-and-verify-token-string client-config token-string) [:claims :user-record-string])]
      (workflows/make-auth (read-string user-record-string)
        {::friend/workflow ::jwt
         ::friend/redirect-on-auth? false
         ::token-string token-string}))))

(defn- authenticate [{:keys [credential-fn token-header service-config] :as config} request]
  ;; when a valid token is present, extend its life
  (if (verify-token config request)
    (extend-token config request)
    ;; no valid token present, we expect a json body with :username and :password
    (if-let [body (:body request)]
      (let [{:keys [username password] :as credentials} (json/parse-string (slurp body) true)] ; FIXME json parsing should be done by the ring-format middleware
        ;; check if the credentials are valid
        (if-let [user-record (and username
                                  password
                                  (credential-fn (with-meta credentials {::friend/workflow ::jwt})))]
          (let [token-time-to-live (service-config :token-time-to-live)
                token-string (make-token-string (user-claim user-record token-time-to-live) service-config)] ; create jwt token
            {:status 200 :headers {token-header token-string}})
          (workflow-deny))) ; credentials are invalid
      {:status 400 :headers {"Content-Type" "text/plain"}}))) ; body is nil, no credentials present 

(defn- login-uri? [config request]
  (and (= (gets :login-uri config (::friend/auth-config request))
          (req/path-info request))
       (= :post (:request-method request))))

(defn workflow [& {:as config}]
  (fn [request]
    (if (login-uri? config request)
      (authenticate config request)
      (verify-token config request))))

;;; ---------------------------------------------------------------------------
;;; library code ends here.


(defroutes app-routes
  (GET "/" [] "Unauthenticated: Hello to you, stranger!\n")
  (GET "/all" req (friend/authenticated (str "Authenticated: Hello to you " (friend/current-authentication req) ", my good friend!!\n")))
  (GET "/user" [] (friend/authorize #{::user} "Authorized: Welcome, dear user!\n"))
  (GET "/admin" [] (friend/authorize #{::admin} "Authorized: Welcome, MASTER!\n"))
  (route/resources "/")
  (route/not-found "Not Found"))

(def secured-app (friend/authenticate
                   app-routes
                   {:allow-anon? true
                    :unauthenticated-handler workflow-deny
                    :login-uri "/authenticate"
                    :workflows [(workflow
                                  :token-header "X-Auth-Token"
                                  :service-config jwt-service-config
                                  :client-config jwt-client-config 
                                  :credential-fn (partial creds/bcrypt-credential-fn users)
                                  :get-user-fn users)]}))

(def app
  (wrap-defaults secured-app api-defaults))

