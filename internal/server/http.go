package server

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

func NewHTTPServer(addr string) *http.Server {
  httpsrv := newHTTPServer()
  r := mux.NewRouter() 
  r.HandleFunc("/", httpsrv.handleProduce).Methods("POST")
  r.HandleFunc("/", httpsrv.handleConsume).Methods("GET")
  return &http.Server{
    Addr: addr,
    Handler: r,
  }
}

type httpServer struct {
  Log *Log
}

func newHTTPServer() *httpServer {
  return &httpServer{
    Log:NewLog(),
  }
}

func (s *httpServer) handleProduce(w http.ResponseWriter, r *http.Request) {
  defer r.Body.Close()

  var req ProduceRequest
  err := json.NewDecoder(r.Body).Decode(&req)
  if err != nil {
    http.Error(w, err.Error(), http.StatusBadRequest)
    return
  }
  off, err := s.Log.Append(req.Record)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  res := ProduceResponse{Offset: off}
  err = json.NewEncoder(w).Encode(res)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
}

func (s *httpServer) handleConsume(w http.ResponseWriter, r *http.Request) {
  defer r.Body.Close()

  var req ConsumeRequest
  err := json.NewDecoder(r.Body).Decode(&req)
  if err != nil {
    http.Error(w, err.Error(), http.StatusBadRequest)
    return
  }
  record, err := s.Log.Read(req.Offset)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  res := ConsumeResponse{Record: record}
  err = json.NewEncoder(w).Encode(res)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }
  
}



type ProduceRequest struct {
  Record Record `json:"record"`
}
type ProduceResponse struct {
  Offset uint64 `json:"offset"`
}
type ConsumeRequest struct {
  Offset uint64 `json:"offset"`
}
type ConsumeResponse struct {
  Record Record `json:"record"`
}

