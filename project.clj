(defproject stepladder-clj "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [org.clojure/core.async "0.2.374"]
                 [org.clojure/tools.logging "0.3.1"]
                 [org.zeromq/curve25519-java "0.1.0"]]
  :main ^:skip-aot stepladder-clj.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
