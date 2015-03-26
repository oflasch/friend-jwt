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
            [clj-jwt.key :refer [private-key]]
            [clj-time.core :refer [now plus seconds minutes hours days months before? after?]]
            [clj-time.coerce :refer [from-long to-long]]
            [cheshire.core :as json]))

(def ^:dynamic *token-time-to-live* (minutes 2))

(def users {"friend" {:username "friend"
                      :password (creds/hash-bcrypt "clojure")
                      :roles #{::user}}
            "oflasch" {:username "oflasch"
                       :password (creds/hash-bcrypt "kaktus")
                       :roles #{::admin}}})

(derive ::admin ::user) ; admins are considered to be also users

(defonce secret "theSecret") ; FIXME plain text secret in the source code says it all...

(defn generate-token-string [claim]
  (-> claim
      jwt
      (sign :HS256 secret)
      to-str)) ;; FIXME use asymmetric encryption

(defn user-claim [user-record]
  {:user-id (user-record :username)
   ;; strip the user record of its password and convert it to an edn string
   :user-record-string (str (dissoc user-record :passwd))
   ;; convert experiation and creation times to longs
   :expiration (to-long (plus (now) *token-time-to-live*))
   :creation (to-long (now))})

(defn verify-jwt-token [jwt-token]
  (let [expiration (from-long (get-in jwt-token [:claims :expiration]))
        creation (from-long (get-in jwt-token [:claims :creation]))
        current-time (now)]
    (and (verify jwt-token secret) ; FIXME use asymmetric encryption
         (not (after? current-time expiration))
         (not (before? current-time creation))
         jwt-token)))

(defn decode-and-verify-token-string [token-string]
  (try
    (-> token-string str->jwt verify-jwt-token)
    (catch Exception e
      nil)))

(defn workflow-deny [& _]
  {:status 401 :headers {"Content-Type" "text/plain"}}) ; FIXME maybe add a body that says "UNAUTHORIZED"

(defn- authenticate [{:keys [credential-fn token-header] :as config} request]
  ;; we expect a json body with :username and :password
  (if-let [body (:body request)]
    (let [{:keys [username password] :as credentials} (json/parse-string (slurp body) true)] ; FIXME json parsing should be done by the ring-format middleware
      ;; check if the credentials are valid
      (if-let [user-record (and username
                                password
                                (credential-fn (with-meta credentials {::friend/workflow ::jwt})))]

        (let [token-string (generate-token-string (user-claim user-record))] ; create jwt token
          (workflows/make-auth user-record
            {::friend/workflow ::jwt
             ::friend/redirect-on-auth? false
             ::token-string token-string})
          {:status 200 :headers {token-header token-string}})

        (workflow-deny))) ; credentials are invalid

    {:status 400 :headers {"Content-Type" "text/plain"}})) ; body is nil, no credentials present 

(defn request->token-string [request token-header]
  ((:headers request) (.toLowerCase token-header)))

;(defn- reconstruct-user-record [json-user-record]
;  (let [reconstructed-roles (into #{} (map (partial keyword "friend-jwt.core") (json-user-record :roles)))] ; FIXME hard-coded namespace
;    {:username (json-user-record :username) :roles reconstructed-roles}))

(defn- read-token [{:keys [token-header] :as config} request]
  (if-let [token-string (request->token-string request token-header)]
    (if-let [user-record-string (get-in (decode-and-verify-token-string token-string) [:claims :user-record-string])]
      (workflows/make-auth (read-string user-record-string)
        {::friend/workflow ::jwt
         ::friend/redirect-on-auth? false
         ::token-string token-string}))))

(defn- login-uri? [config request]
  (and (= (gets :login-uri config (::friend/auth-config request))
          (req/path-info request))
       (= :post (:request-method request))))

(defn workflow [& {:as config}]
  (fn [request]
    (if
      (login-uri? config request)
      (authenticate config request)
      (read-token config request))))

(defroutes app-routes
  (GET "/" [] "Unauthenticated: Hello to you, stranger!\n")
  (GET "/all" req (friend/authenticated (str "Authenticated: Hello to you " (friend/current-authentication req) ", my good friend!!\n")))
  (GET "/user" [] (friend/authorize #{::user} "Authorized: Welcome, dear user!\n"))
  (GET "/admin" [] (friend/authorize #{::admin} "Authorized: Welcome, MASTER!\n"))
  ;;(POST "/extend-token" []
  ;;  (friend/authenticated
  ;;    (friend-token/extend-life
  ;;      {:status 200 :headers {}}))) ; TODO add a means to renew a token
  (route/resources "/")
  (route/not-found "Not Found"))

(def secured-app (friend/authenticate
                   app-routes
                   {:allow-anon? true
                    :unauthenticated-handler workflow-deny
                    :login-uri "/authenticate"
                    :workflows [(workflow
                                  :token-header "X-Auth-Token"
                                  :credential-fn (partial creds/bcrypt-credential-fn users)
                                  :get-user-fn users)]}))

(def app
  (wrap-defaults secured-app api-defaults))

