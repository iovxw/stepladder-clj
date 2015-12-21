(ns nsp.ecdh
  (:import (org.zeromq.djb.Curve25519)
           (java.security SecureRandom)))

(def ^:private r (SecureRandom.))

(defn random-byte-array [length]
  (let [b (byte-array length)]
    (.nextBytes r b)
    b))

(defn keygen
  ([] (keygen (random-byte-array 32)))
  ([r]
   (let [public-key (byte-array 32)
         private-key r]
     (djb.Curve25519/keygen public-key nil private-key)
     [private-key public-key])))

(defn curve [private-key p-public-key]
  (let [shared-secret (byte-array 32)]
    (djb.Curve25519/curve shared-secret private-key p-public-key)
    shared-secret))
