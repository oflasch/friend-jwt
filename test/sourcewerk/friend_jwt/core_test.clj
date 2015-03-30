(ns sourcewerk.friend-jwt.core-test
  (:require [clojure.test :refer :all]
            [ring.mock.request :refer :all]
            [cemerick.friend :as friend]
            [cemerick.friend.credentials :as creds]
            [clj-time.core :refer [seconds minutes now date-time]]
            [sourcewerk.friend-jwt.core :refer :all]))

(def test-users {"friend" {:username "friend"
                           :password (creds/hash-bcrypt "clojure")
                           :roles #{::user}}
                 "greg" {:username "greg"
                         :password (creds/hash-bcrypt "kaktus")
                         :roles #{::admin}}})

(derive ::admin ::user) ; admins are considered to be also users

(def test-workflow-HS256
  (workflow
    :login-uri "/auth"
    :credential-fn (partial creds/bcrypt-credential-fn test-users)
    :get-user-fn test-users
    :token-header "X-Auth-Token"
    :service-config {:algorithm :HS256
                     :private-key "secret"
                     :token-time-to-live (minutes 5)} 
    :client-config {:algorithm :HS256
                    :public-key "secret"} ))

(deftest worflow-test
  (testing "workflow with HS256 algorithm"
    (testing "authentication request without credentials"
      (is (= (test-workflow-HS256 (request :post "/auth"))
             {:status 400
              :headers {"Content-Type" "text/plain"}})))
    (testing "authentication request with invalid credentials"
      (is (= (test-workflow-HS256
               (-> (request :post "/auth")
                 (body "{\"username\": \"greg\", \"password\": \"Karamba\"}")))
             {:status 401
              :headers {"Content-Type" "text/plain"}})))
    (testing "authentication request with valid credentials"
      (is (= (with-redefs [now (fn [& _] (date-time 1980 1 1 12 0))]
               (test-workflow-HS256
                 (-> (request :post "/auth")
                   (body "{\"username\": \"greg\", \"password\": \"kaktus\"}"))))
             {:status 200 
              :headers {"Content-Type" "text/plain"
                        "X-Auth-Token" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyLXJlY29yZC1zdHJpbmciOiJ7OnVzZXJuYW1lIFwiZ3JlZ1wiLCA6cm9sZXMgI3s6ZnJpZW5kLWp3dC5jb3JlLXRlc3RcL2FkbWlufX0iLCJzdWIiOiJncmVnIiwiZXhwIjozMTU1NzYzMDAsImlhdCI6MzE1NTc2MDAwfQ.-XPyaW1N70MVtyo4EQMBz3S6IfXpvEI3oqfGmx-YB9k"}})))
    (testing "extension request with invalid token"
      (is (= (with-redefs [now (fn [& _] (date-time 1980 1 1 12 0))]
               (test-workflow-HS256
                 (-> (request :post "/auth")
                   (header "X-Auth-Token" "XyJhbGciOiJIXXXXNiIsInR5cCI6IkpXVCJ9.eyJ1c2VyLXJlY29yZC1zdHJpbmciOiJ7OnVzZXJuYW1lIFwiZ3JlZ1wiLCA6cm9sZXMgI3s6ZnJpZW5kLWp3dC5jb3JlLXRlc3RcL2FkbWlufX0iLCJzdWIiOiJncmVnIiwiZXhwIjozMTU1NzYzMDAsImlhdCI6MzE1NTc2MDAwfQ.-XPyaW1N70MVtyo4EQMBz3S6IfXpvEI3oqfGmx-YB9k"))))
             {:status 400 
              :headers {"Content-Type" "text/plain"}})))
    (testing "extension request with expired token"
      (is (= (with-redefs [now (fn [& _] (date-time 1980 1 1 12 6))]
               (test-workflow-HS256
                 (-> (request :post "/auth")
                   (header "X-Auth-Token" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyLXJlY29yZC1zdHJpbmciOiJ7OnVzZXJuYW1lIFwiZ3JlZ1wiLCA6cm9sZXMgI3s6ZnJpZW5kLWp3dC5jb3JlLXRlc3RcL2FkbWlufX0iLCJzdWIiOiJncmVnIiwiZXhwIjozMTU1NzYzMDAsImlhdCI6MzE1NTc2MDAwfQ.-XPyaW1N70MVtyo4EQMBz3S6IfXpvEI3oqfGmx-YB9k"))))
             {:status 400 
              :headers {"Content-Type" "text/plain"}})))
    (testing "extension request with forged token"
      (is (= (with-redefs [now (fn [& _] (date-time 1980 1 1 11 0))]
               (test-workflow-HS256
                 (-> (request :post "/auth")
                   (header "X-Auth-Token" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyLXJlY29yZC1zdHJpbmciOiJ7OnVzZXJuYW1lIFwiZ3JlZ1wiLCA6cm9sZXMgI3s6ZnJpZW5kLWp3dC5jb3JlLXRlc3RcL2FkbWlufX0iLCJzdWIiOiJncmVnIiwiZXhwIjozMTU1NzYzMDAsImlhdCI6MzE1NTc2MDAwfQ.-XPyaW1N70MVtyo4EQMBz3S6IfXpvEI3oqfGmx-YB9k"))))
             {:status 400 
              :headers {"Content-Type" "text/plain"}})))
    (testing "extension request with valid token"
      (is (= (with-redefs [now (fn [& _] (date-time 1980 1 1 12 4))]
               (test-workflow-HS256
                 (-> (request :post "/auth")
                   (header "X-Auth-Token" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyLXJlY29yZC1zdHJpbmciOiJ7OnVzZXJuYW1lIFwiZ3JlZ1wiLCA6cm9sZXMgI3s6ZnJpZW5kLWp3dC5jb3JlLXRlc3RcL2FkbWlufX0iLCJzdWIiOiJncmVnIiwiZXhwIjozMTU1NzYzMDAsImlhdCI6MzE1NTc2MDAwfQ.-XPyaW1N70MVtyo4EQMBz3S6IfXpvEI3oqfGmx-YB9k"))))
             {:status 200 
              :headers {"Content-Type" "text/plain"
                        "X-Auth-Token" "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyLXJlY29yZC1zdHJpbmciOiJ7OnVzZXJuYW1lIFwiZ3JlZ1wiLCA6cm9sZXMgI3s6ZnJpZW5kLWp3dC5jb3JlLXRlc3RcL2FkbWlufX0iLCJzdWIiOiJncmVnIiwiZXhwIjozMTU1NzY1NDAsImlhdCI6MzE1NTc2MjQwfQ.dPolqs3UM34EqvAxvj9Ko_bAuNrl4tn9wh4sOs1W0Eo"}}))) ))

;; TODO test extension request for a deleted user
