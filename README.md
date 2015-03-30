# friend-jwt

A [JSON Web Token (JWT)](http://jwt.io) workflow for APIs using the
[Friend](https://github.com/cemerick/friend) middleware for authentication.

## Rationale

friend-jwt provides a JWT-based workflow for APIs using the Friend middleware
for authentication and authorization. This workflow is designed for use in
an authentication micro-service.

Important characteristics:

* based on the [clj-jwt](https://github.com/liquidz/clj-jwt) library
* generated tokens contain a `user-record-string` claim 
  * it contains the subject's identiy (friend username) and roles encoded as
    an [edn](https://clojure.github.io/clojure/clojure.edn-api.html) string
  * this claim can be used to authorize a request without access to the
    friend user database, improving simplicity and scalability
* generated tokens are not stored in any way
  * this makes it impossible to retract tokens, therefore token lifetime
    should be limited to a reasonable short duration (e.g. 1 to 10 minutes)
  * system clocks of both the authentication micro-service and of services
    that use tokens to authorize requests must be reliable
  * token lifetime can be extended without providing friend credentials
    again, see the usage example below

## Installation

friend-jwt is available in Clojars. Add this `:dependency` to your Leiningen
`project.clj`:

```clojure
[sourcewerk/friend-jwt "0.1.0-SNAPSHOT"]
```

## Usage

The following code implements a very basic authentication service (also
available [in the repo](../blob/master/src/sourcewerk/friend_jwt/examples/auth_service.clj)):

```clojure
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
```

This service can be consumed via JSON requests. The following examples use 
[cURL](http://curl.haxx.se):

```bash
TODO
```

## License

Copyright © 2015 [sourcewerk UG](http://sourcewerk.de), Oliver Flasch 

Distributed under the Eclipse Public License version 1.0.
