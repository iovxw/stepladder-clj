(ns nsp.core-test
  (:require [clojure.test :refer :all]
            [clojure.core.async :refer :all]
            [clojure.tools.logging :as log]
            [nsp.core :as nsp]))

(defn handle [client]
  (nsp/close client))

(defn server [port key]
  (let [ln (nsp/listen-nsp port key)]
    (go-loop []
      (try (handle (nsp/accept ln))
           (catch Exception e
             (log/error e "An error in handle")))
      (recur))))

(defn request [host port key]
  (let [server (nsp/dial-nsp host port key)]
    (nsp/close server)))

(deftest benchmark
  (testing "benchmark"
    (let [k (byte-array [0 1 2 3 4 5 6 7 8 9])
          host "127.0.0.1"
          port 8088
          rn 10000 ; 请求数量
          start (System/nanoTime)]
      (server 8088 k) ; 本地运行一个服务器
      (doseq [n (range rn)]
        (request host port k))
      (let [t-msec (/ (double (- (System/nanoTime) start)) 1000000.0)]
        (printf "Time: %s msecs%n" t-msec)
        (printf "%s req/s"
                (/ 1.0 (/ (/ t-msec 1000.0) rn)))))))
