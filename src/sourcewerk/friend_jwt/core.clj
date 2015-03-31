(ns sourcewerk.friend-jwt.core
  (:require [ring.middleware.defaults :refer :all]
            [ring.util.request :refer [path-info]]
            [cemerick.friend :as friend]
            [cemerick.friend.credentials :as creds]
            [cemerick.friend.workflows :as workflows]
            [cemerick.friend.util :refer [gets]]
            [clj-jwt.core :refer :all]
            [clj-time.core :refer [now plus before? after?]]
            [clj-jwt.intdate :refer [intdate->joda-time]]
            [cheshire.core :as json]))

;; TODO add support for the claims defined in https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
(defn- make-user-claim [service-config user-record]
  {;; strip the user record of its password and convert it to an edn string
   :user-record-string (str (dissoc user-record :password))
   ;; standard claims
   :sub (user-record :username)
   :exp (plus (now) (service-config :token-time-to-live))
   :iat (now)})

(defn- make-jwt-token [service-config user-record]
  (-> (make-user-claim service-config user-record)
      jwt
      (sign (service-config :algorithm) (service-config :private-key))))

(defn- intdate->joda-time-or-nil [intdate]
  (if (integer? intdate)
    (intdate->joda-time intdate)
    nil))

(defn- verify-jwt-token [client-config jwt-token]
  (let [expiration (intdate->joda-time-or-nil (get-in jwt-token [:claims :exp]))
        issued-at (intdate->joda-time-or-nil (get-in jwt-token [:claims :iat]))
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

(defn- request->token-string [request token-header]
  ((:headers request) (.toLowerCase token-header)))

(defn- extend-token [{:keys [get-user-fn token-header client-config service-config] :as config} request]
  (when-let [token-string (request->token-string request token-header)]
    (when-let [token-user-record-string (get-in (decode-and-verify-token-string client-config token-string) [:claims :user-record-string])]
      (let [token-user-record (read-string token-user-record-string)
            token-user-name (:username token-user-record)]
        (when-let [user-record (get-user-fn token-user-name)]
          (let [token-string (to-str (make-jwt-token service-config user-record))] ; create jwt token string
            {:status 200 :headers {"Content-Type" "text/plain"
                                   token-header token-string}}))))))

(defn- verify-token [{:keys [token-header client-config] :as config} request]
  (when-let [token-string (request->token-string request token-header)]
    (when-let [user-record-string (get-in (decode-and-verify-token-string client-config token-string) [:claims :user-record-string])]
      (workflows/make-auth (read-string user-record-string)
        {::friend/workflow ::jwt
         ::friend/redirect-on-auth? false
         ::token-string token-string}))))

(defn workflow-deny [& _] {:status 401 :headers {"Content-Type" "text/plain"}})

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
          (let [token-string (to-str (make-jwt-token service-config user-record))] ; create jwt token string
            {:status 200 :headers {"Content-Type" "text/plain"
                                   token-header token-string}})
          (workflow-deny))) ; credentials are invalid
      {:status 400 :headers {"Content-Type" "text/plain"}}))) ; body is nil, no credentials present 

(defn- login-uri? [config request]
  (and (= (gets :login-uri config (::friend/auth-config request))
          (path-info request))
       (= :post (:request-method request))))

(defn workflow [& {:as config}]
  "A friend workflow using JSON Web Tokens (JWT)."
  (fn [request]
    (if (login-uri? config request)
      (authenticate config request)
      (verify-token config request))))

