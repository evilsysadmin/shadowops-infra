package main

import (
 "strings"
 "testing"
)

func TestNativeAccountCredentialPipeParsing(t *testing.T){
 good:="correct-horse-battery-staple"
 for _,test:=range []struct{name,input string;accept bool}{
  {"single secret",good,true},
  {"optional final newline",good+"\n",true},
  {"empty","",false},
  {"too short","short-password",false},
  {"embedded newline",good+"\nanother",false},
  {"carriage return",good+"\r\n",false},
  {"nul byte",good+"\x00",false},
  {"invalid UTF-8",good+"\xff",false},
  {"oversized",strings.Repeat("x",4097),false},
  {"extra newline",good+"\n\n",false},
 }{
  t.Run(test.name,func(t *testing.T){
   actual,err:=readNativePassword(strings.NewReader(test.input))
   if test.accept && (err!=nil || actual!=good){t.Fatal("valid credential not preserved")}
   if !test.accept && (err==nil || actual!=""){t.Fatal("invalid credential accepted")}
  })
 }
}
