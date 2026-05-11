package main

import "testing"

func TestClassifyWeChatSignatureAdHoc(t *testing.T) {
	st := classifyWeChatSignature(`Executable=/Applications/WeChat.app/Contents/MacOS/WeChat
Identifier=com.tencent.xinWeChat
Format=app bundle with Mach-O universal
CodeDirectory v=20500 size=123 flags=0x2(adhoc) hashes=1+5 location=embedded
Signature=adhoc
TeamIdentifier=not set`)
	if !st.AdHoc {
		t.Fatalf("expected ad-hoc signature")
	}
	if st.Runtime {
		t.Fatalf("did not expect runtime signature")
	}
}

func TestClassifyWeChatSignatureRuntime(t *testing.T) {
	st := classifyWeChatSignature(`Executable=/Applications/WeChat.app/Contents/MacOS/WeChat
Identifier=com.tencent.xinWeChat
Format=app bundle with Mach-O universal
CodeDirectory v=20500 size=19617 flags=0x10000(runtime) hashes=602+7 location=embedded
Signature size=9092
TeamIdentifier=5A4RE8SF68`)
	if !st.Runtime {
		t.Fatalf("expected hardened runtime signature")
	}
	if st.AdHoc {
		t.Fatalf("did not expect ad-hoc signature")
	}
}
