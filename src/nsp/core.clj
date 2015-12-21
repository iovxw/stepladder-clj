(ns nsp.core
  (:import (java.net Socket ServerSocket)
           (java.io InputStream OutputStream)
           (java.util Arrays Random)
           (java.security MessageDigest))
  (:require [nsp.ecdh :as ecdh]
            [nsp.aes :as aes])
  (:refer-clojure :exclude [read]))

(defprotocol Reader
  (read [this buf]))

(defprotocol Writer
  (write [this data]))

(defprotocol Listener
  (accept [this]))

(defprotocol Closer
  (close [this]))

(deftype TCPConn [socket input-stream output-stream]
  Reader
  (read [this buf]
    (.read input-stream buf))
  Writer
  (write [this data]
    (.write output-stream data)
    (.flush output-stream))
  Closer
  (close [this]
    (.close input-stream)
    (.close output-stream)
    (.close socket)))

(defn dail-tcp [host port]
  (let [socket (Socket. host port)]
    (TCPConn. socket (.getInputStream socket) (.getOutputStream socket))))

(deftype TCPListener [server-socket]
  Listener
  (accept [this]
    (let [socket (.accept server-socket)]
      (TCPConn. socket (.getInputStream socket) (.getOutputStream socket))))
  Closer
  (close [this]
    (.close server-socket)))

(defn listen-tcp [port]
  (TCPListener. (ServerSocket. port)))

(deftype NSPConn [tcp-conn read-state write-state]
  Reader
  (read [this buf]
    (let [n (read tcp-conn buf)
          data (Arrays/copyOfRange buf 0 n)]
      (aes/stream-decrypt-ctr data read-state)
      (System/arraycopy data 0 buf 0 n)
      n))
  Writer
  (write [this data]
    (aes/stream-encrypt-ctr data write-state)
    (write tcp-conn data))
  Closer
  (close [this]
    (close tcp-conn)))

(defn xor-placeholder-length [len key]
  (bit-xor (unchecked-byte len) (apply bit-xor key)))

(def ^:private r (Random.))

(defn make-placeholder [key]
  (let [len (rand-int 32)
        placeholder (byte-array (+ len 1))]
    (.nextBytes r placeholder)
    (aset-byte placeholder 0 (xor-placeholder-length len key))
    placeholder))

(defn read-placeholder [conn key]
  (let [length (byte-array 1)]
    (read conn length)
    (read conn
          (byte-array (xor-placeholder-length (first length) key)))))

(defn append-byte-array [& array]
  (let [size (reduce #(+ %1 (count %2)) 0 array)
        result (byte-array size)]
    (reduce (fn [n b-array]
              (let [length (count b-array)]
                (System/arraycopy b-array 0 result n length)
                (+ n length)))
            0 array)
    result))

(def ^:private sha256 (MessageDigest/getInstance "SHA-256"))

(defn dail-nsp [host port key]
  (let [conn (dail-tcp host port)]
    ; 握手
    (let [[private-key public-key] (ecdh/keygen)]
      (write conn (append-byte-array
                    (make-placeholder key)
                    public-key
                    (make-placeholder key)))
      (read-placeholder conn key)
      (let [buf (byte-array 64)
            n (read conn buf)]
        (when (not= n 64)
          (throw (Exception. ""))) ; TODO
        (read-placeholder conn key)
        (let [server-public-key (Arrays/copyOfRange buf 0 32)
              hash (Arrays/copyOfRange buf 32 64)
              result (ecdh/curve private-key server-public-key)]
          (when-not (Arrays/equals
                      (.digest sha256 (append-byte-array key result))
                      hash)
            (throw (Exception. "身份验证失败，可能已遭到中间人攻击")))
          (let [aes-key result
                iv-read (Arrays/copyOfRange result 0 16)
                iv-write (Arrays/copyOfRange result 16 32)
                read-state (aes/new-ctr-stream aes-key iv-read)
                write-state (aes/new-ctr-stream aes-key iv-write)]
            (NSPConn. conn read-state write-state)))))))

(deftype NSPListener [tcp-listener key]
  Listener
  (accept [this]
    (let [conn (accept tcp-listener)]
      ; 握手
      (read-placeholder conn key)
      (let [client-public-key (byte-array 32)
            n (read conn client-public-key)]
        (when (not= n 32)
          (throw (Exception. ""))) ; TODO
        (read-placeholder conn key)

        (let [[private-key public-key] (ecdh/keygen)
              result (ecdh/curve private-key client-public-key)
              hash (.digest sha256 (append-byte-array key result))]
          (write conn (append-byte-array
                        (make-placeholder key)
                        public-key
                        hash
                        (make-placeholder key)))
          (let [aes-key result
                iv-write (Arrays/copyOfRange result 0 16)
                iv-read (Arrays/copyOfRange result 16 32)
                write-state (aes/new-ctr-stream aes-key iv-write)
                read-state (aes/new-ctr-stream aes-key iv-read)]
            (NSPConn. conn read-state write-state))))))
  Closer
  (close [this]
    (close tcp-listener)))

(defn listen-nsp [port key]
  (NSPListener. (listen-tcp port) key))
