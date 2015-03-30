(ns sourcewerk.friend-jwt.examples.auth-service
  (:require [sourcewerk.friend-jwt.core :as friend-jwt]
            [ring.adapter.jetty :as jetty]
            [ring.middleware.defaults :refer :all]
            [ring.util.request :as req]
            [compojure.core :refer :all]
            [compojure.route :as route]
            [cemerick.friend :as friend]
            [cemerick.friend.credentials :as creds]
            [cemerick.friend.util :refer [gets]]
            [clj-jwt.key :refer [public-key private-key]]
            [clj-time.core :refer [minutes]]
            [clj-jwt.intdate :refer [intdate->joda-time]]))

(def users {"friend" {:username "friend"
                      :password (creds/hash-bcrypt "clojure")
                      :roles #{::user}}
            "greg" {:username "greg"
                    :password (creds/hash-bcrypt "kaktus")
                    :roles #{::admin}}})

(derive ::admin ::user) ; admins are considered to be also users

(def jwt-service-config
  {:algorithm :HS256
   :private-key "secret" ; FIXME never put a plain text secret in the source code!
   :token-time-to-live (minutes 2)})

(def jwt-client-config
  {:algorithm :HS256
   :public-key "secret"}) ; FIXME never put a plain text secret in the source code! 

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
                    :unauthenticated-handler friend-jwt/workflow-deny
                    :login-uri "/authenticate"
                    :workflows [(friend-jwt/workflow
                                  :token-header "X-Auth-Token"
                                  :service-config jwt-service-config
                                  :client-config jwt-client-config 
                                  :credential-fn (partial creds/bcrypt-credential-fn users)
                                  :get-user-fn users)]}))

(def app
  (wrap-defaults secured-app api-defaults))

(defn -main [& args]
  (jetty/run-jetty app {:port 3000}))

