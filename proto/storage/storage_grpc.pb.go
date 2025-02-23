// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v5.28.3
// source: storage.proto

package storage

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	Storage_PostExternalId_FullMethodName   = "/storage.Storage/PostExternalId"
	Storage_PostRefferenceNo_FullMethodName = "/storage.Storage/PostRefferenceNo"
	Storage_PostTrxId_FullMethodName        = "/storage.Storage/PostTrxId"
	Storage_GetTrxId_FullMethodName         = "/storage.Storage/GetTrxId"
)

// StorageClient is the client API for Storage service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// Interface exported by the server.
type StorageClient interface {
	PostExternalId(ctx context.Context, in *ExternalIdRequest, opts ...grpc.CallOption) (*ExternalIdResponse, error)
	PostRefferenceNo(ctx context.Context, in *ReffNoRequest, opts ...grpc.CallOption) (*ReffNoResponse, error)
	PostTrxId(ctx context.Context, in *TrxIdRequest, opts ...grpc.CallOption) (*TrxIdResponse, error)
	GetTrxId(ctx context.Context, in *TrxIdRequest, opts ...grpc.CallOption) (*TrxIdResponse, error)
}

type storageClient struct {
	cc grpc.ClientConnInterface
}

func NewStorageClient(cc grpc.ClientConnInterface) StorageClient {
	return &storageClient{cc}
}

func (c *storageClient) PostExternalId(ctx context.Context, in *ExternalIdRequest, opts ...grpc.CallOption) (*ExternalIdResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ExternalIdResponse)
	err := c.cc.Invoke(ctx, Storage_PostExternalId_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageClient) PostRefferenceNo(ctx context.Context, in *ReffNoRequest, opts ...grpc.CallOption) (*ReffNoResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ReffNoResponse)
	err := c.cc.Invoke(ctx, Storage_PostRefferenceNo_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageClient) PostTrxId(ctx context.Context, in *TrxIdRequest, opts ...grpc.CallOption) (*TrxIdResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(TrxIdResponse)
	err := c.cc.Invoke(ctx, Storage_PostTrxId_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *storageClient) GetTrxId(ctx context.Context, in *TrxIdRequest, opts ...grpc.CallOption) (*TrxIdResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(TrxIdResponse)
	err := c.cc.Invoke(ctx, Storage_GetTrxId_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// StorageServer is the server API for Storage service.
// All implementations must embed UnimplementedStorageServer
// for forward compatibility.
//
// Interface exported by the server.
type StorageServer interface {
	PostExternalId(context.Context, *ExternalIdRequest) (*ExternalIdResponse, error)
	PostRefferenceNo(context.Context, *ReffNoRequest) (*ReffNoResponse, error)
	PostTrxId(context.Context, *TrxIdRequest) (*TrxIdResponse, error)
	GetTrxId(context.Context, *TrxIdRequest) (*TrxIdResponse, error)
	mustEmbedUnimplementedStorageServer()
}

// UnimplementedStorageServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedStorageServer struct{}

func (UnimplementedStorageServer) PostExternalId(context.Context, *ExternalIdRequest) (*ExternalIdResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PostExternalId not implemented")
}
func (UnimplementedStorageServer) PostRefferenceNo(context.Context, *ReffNoRequest) (*ReffNoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PostRefferenceNo not implemented")
}
func (UnimplementedStorageServer) PostTrxId(context.Context, *TrxIdRequest) (*TrxIdResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PostTrxId not implemented")
}
func (UnimplementedStorageServer) GetTrxId(context.Context, *TrxIdRequest) (*TrxIdResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetTrxId not implemented")
}
func (UnimplementedStorageServer) mustEmbedUnimplementedStorageServer() {}
func (UnimplementedStorageServer) testEmbeddedByValue()                 {}

// UnsafeStorageServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to StorageServer will
// result in compilation errors.
type UnsafeStorageServer interface {
	mustEmbedUnimplementedStorageServer()
}

func RegisterStorageServer(s grpc.ServiceRegistrar, srv StorageServer) {
	// If the following call pancis, it indicates UnimplementedStorageServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Storage_ServiceDesc, srv)
}

func _Storage_PostExternalId_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExternalIdRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServer).PostExternalId(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Storage_PostExternalId_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServer).PostExternalId(ctx, req.(*ExternalIdRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Storage_PostRefferenceNo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ReffNoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServer).PostRefferenceNo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Storage_PostRefferenceNo_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServer).PostRefferenceNo(ctx, req.(*ReffNoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Storage_PostTrxId_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TrxIdRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServer).PostTrxId(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Storage_PostTrxId_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServer).PostTrxId(ctx, req.(*TrxIdRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Storage_GetTrxId_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(TrxIdRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StorageServer).GetTrxId(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Storage_GetTrxId_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(StorageServer).GetTrxId(ctx, req.(*TrxIdRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Storage_ServiceDesc is the grpc.ServiceDesc for Storage service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Storage_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "storage.Storage",
	HandlerType: (*StorageServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "PostExternalId",
			Handler:    _Storage_PostExternalId_Handler,
		},
		{
			MethodName: "PostRefferenceNo",
			Handler:    _Storage_PostRefferenceNo_Handler,
		},
		{
			MethodName: "PostTrxId",
			Handler:    _Storage_PostTrxId_Handler,
		},
		{
			MethodName: "GetTrxId",
			Handler:    _Storage_GetTrxId_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "storage.proto",
}
