(defproject sourcewerk/friend-jwt "0.1.0-SNAPSHOT"
  :description "A JSON Web Token (JWT) workflow for APIs using the Friend middleware for authentication."
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [com.cemerick/friend "0.2.1"]
                 [clj-jwt "0.0.12"]
                 [clj-time "0.9.0"]
                 [cheshire "5.4.0"]
                 ;; for testing...
                 [ring/ring-core "1.3.2"]
                 [ring/ring-jetty-adapter "1.3.2"]
                 [ring/ring-defaults "0.1.4"]
                 [ring/ring-mock "0.2.0"]
                 [compojure "1.3.2"]]
  :main sourcewerk.friend-jwt.examples.auth-service)
