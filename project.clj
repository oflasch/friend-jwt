(defproject friend-jwt "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :plugins [[lein-ring "0.9.3"]] ; for testing
  :ring {:handler friend-jwt.core/app} ; for testing
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [com.cemerick/friend "0.2.1"]
                 [clj-jwt "0.0.12"]
                 [clj-time "0.9.0"]
                 [cheshire "5.4.0"] ; for JSON parsing
                 ;; for testing...
                 [ring/ring-core "1.3.2"]
                 [ring/ring-jetty-adapter "1.3.2"]
                 [ring/ring-defaults "0.1.4"]
                 [compojure "1.3.2"]])
