// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v5.28.3
// source: signature.proto

package signature

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AuthSignatureRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version    string `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	ClientId   string `protobuf:"bytes,2,opt,name=clientId,proto3" json:"clientId,omitempty"`
	XTimestamp string `protobuf:"bytes,3,opt,name=xTimestamp,json=X-Timestamp,proto3" json:"xTimestamp,omitempty"`
}

func (x *AuthSignatureRequest) Reset() {
	*x = AuthSignatureRequest{}
	mi := &file_signature_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AuthSignatureRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthSignatureRequest) ProtoMessage() {}

func (x *AuthSignatureRequest) ProtoReflect() protoreflect.Message {
	mi := &file_signature_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthSignatureRequest.ProtoReflect.Descriptor instead.
func (*AuthSignatureRequest) Descriptor() ([]byte, []int) {
	return file_signature_proto_rawDescGZIP(), []int{0}
}

func (x *AuthSignatureRequest) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *AuthSignatureRequest) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *AuthSignatureRequest) GetXTimestamp() string {
	if x != nil {
		return x.XTimestamp
	}
	return ""
}

type SignatureResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ResponseCode    string `protobuf:"bytes,1,opt,name=responseCode,proto3" json:"responseCode,omitempty"`
	ResponseMessage string `protobuf:"bytes,2,opt,name=responseMessage,proto3" json:"responseMessage,omitempty"`
	Signature       string `protobuf:"bytes,3,opt,name=signature,proto3" json:"signature,omitempty"`
}

func (x *SignatureResponse) Reset() {
	*x = SignatureResponse{}
	mi := &file_signature_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SignatureResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignatureResponse) ProtoMessage() {}

func (x *SignatureResponse) ProtoReflect() protoreflect.Message {
	mi := &file_signature_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignatureResponse.ProtoReflect.Descriptor instead.
func (*SignatureResponse) Descriptor() ([]byte, []int) {
	return file_signature_proto_rawDescGZIP(), []int{1}
}

func (x *SignatureResponse) GetResponseCode() string {
	if x != nil {
		return x.ResponseCode
	}
	return ""
}

func (x *SignatureResponse) GetResponseMessage() string {
	if x != nil {
		return x.ResponseMessage
	}
	return ""
}

func (x *SignatureResponse) GetSignature() string {
	if x != nil {
		return x.Signature
	}
	return ""
}

type TrxSignatureRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version      string `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	Method       string `protobuf:"bytes,2,opt,name=method,proto3" json:"method,omitempty"`
	UrlPath      string `protobuf:"bytes,3,opt,name=urlPath,proto3" json:"urlPath,omitempty"`
	AccessToken  string `protobuf:"bytes,4,opt,name=accessToken,proto3" json:"accessToken,omitempty"`
	Body         string `protobuf:"bytes,5,opt,name=body,proto3" json:"body,omitempty"`
	XTimestamp   string `protobuf:"bytes,6,opt,name=xTimestamp,json=X-Timestamp,proto3" json:"xTimestamp,omitempty"`
	ClientSecret string `protobuf:"bytes,7,opt,name=clientSecret,proto3" json:"clientSecret,omitempty"`
	ClientId     string `protobuf:"bytes,8,opt,name=clientId,proto3" json:"clientId,omitempty"`
}

func (x *TrxSignatureRequest) Reset() {
	*x = TrxSignatureRequest{}
	mi := &file_signature_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TrxSignatureRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TrxSignatureRequest) ProtoMessage() {}

func (x *TrxSignatureRequest) ProtoReflect() protoreflect.Message {
	mi := &file_signature_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TrxSignatureRequest.ProtoReflect.Descriptor instead.
func (*TrxSignatureRequest) Descriptor() ([]byte, []int) {
	return file_signature_proto_rawDescGZIP(), []int{2}
}

func (x *TrxSignatureRequest) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *TrxSignatureRequest) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *TrxSignatureRequest) GetUrlPath() string {
	if x != nil {
		return x.UrlPath
	}
	return ""
}

func (x *TrxSignatureRequest) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

func (x *TrxSignatureRequest) GetBody() string {
	if x != nil {
		return x.Body
	}
	return ""
}

func (x *TrxSignatureRequest) GetXTimestamp() string {
	if x != nil {
		return x.XTimestamp
	}
	return ""
}

func (x *TrxSignatureRequest) GetClientSecret() string {
	if x != nil {
		return x.ClientSecret
	}
	return ""
}

func (x *TrxSignatureRequest) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

var File_signature_proto protoreflect.FileDescriptor

var file_signature_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0x6d, 0x0a, 0x14,
	0x41, 0x75, 0x74, 0x68, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1a,
	0x0a, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x08, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x1f, 0x0a, 0x0a, 0x78, 0x54,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b,
	0x58, 0x2d, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x22, 0x7f, 0x0a, 0x11, 0x53,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x22, 0x0a, 0x0c, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x43, 0x6f, 0x64, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x43, 0x6f, 0x64, 0x65, 0x12, 0x28, 0x0a, 0x0f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x72,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1c,
	0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x22, 0xf8, 0x01, 0x0a,
	0x13, 0x54, 0x72, 0x78, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x16,
	0x0a, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06,
	0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x12, 0x18, 0x0a, 0x07, 0x75, 0x72, 0x6c, 0x50, 0x61, 0x74,
	0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x75, 0x72, 0x6c, 0x50, 0x61, 0x74, 0x68,
	0x12, 0x20, 0x0a, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x62, 0x6f, 0x64, 0x79, 0x12, 0x1f, 0x0a, 0x0a, 0x78, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x58, 0x2d, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x22, 0x0a, 0x0c, 0x63, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x32, 0xb5, 0x01, 0x0a, 0x09, 0x53, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x54, 0x0a, 0x11, 0x50, 0x6f, 0x73, 0x74, 0x41, 0x75, 0x74,
	0x68, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x1f, 0x2e, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x53, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1c, 0x2e, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x52, 0x0a, 0x10, 0x50,
	0x6f, 0x73, 0x74, 0x54, 0x72, 0x78, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12,
	0x1e, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x54, 0x72, 0x78, 0x53,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x1c, 0x2e, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x2e, 0x53, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42,
	0x13, 0x5a, 0x11, 0x2e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x69, 0x67, 0x6e, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_signature_proto_rawDescOnce sync.Once
	file_signature_proto_rawDescData = file_signature_proto_rawDesc
)

func file_signature_proto_rawDescGZIP() []byte {
	file_signature_proto_rawDescOnce.Do(func() {
		file_signature_proto_rawDescData = protoimpl.X.CompressGZIP(file_signature_proto_rawDescData)
	})
	return file_signature_proto_rawDescData
}

var file_signature_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_signature_proto_goTypes = []any{
	(*AuthSignatureRequest)(nil), // 0: signature.AuthSignatureRequest
	(*SignatureResponse)(nil),    // 1: signature.SignatureResponse
	(*TrxSignatureRequest)(nil),  // 2: signature.TrxSignatureRequest
}
var file_signature_proto_depIdxs = []int32{
	0, // 0: signature.Signature.PostAuthSignature:input_type -> signature.AuthSignatureRequest
	2, // 1: signature.Signature.PostTrxSignature:input_type -> signature.TrxSignatureRequest
	1, // 2: signature.Signature.PostAuthSignature:output_type -> signature.SignatureResponse
	1, // 3: signature.Signature.PostTrxSignature:output_type -> signature.SignatureResponse
	2, // [2:4] is the sub-list for method output_type
	0, // [0:2] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_signature_proto_init() }
func file_signature_proto_init() {
	if File_signature_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_signature_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_signature_proto_goTypes,
		DependencyIndexes: file_signature_proto_depIdxs,
		MessageInfos:      file_signature_proto_msgTypes,
	}.Build()
	File_signature_proto = out.File
	file_signature_proto_rawDesc = nil
	file_signature_proto_goTypes = nil
	file_signature_proto_depIdxs = nil
}
