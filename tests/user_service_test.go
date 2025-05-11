package tests

import (
	"context"
	"fmt"
	"testing"
	"user-service-go/proto"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Mock server that doesn't use DB or JWT
type MockUserServiceServer struct {
	proto.UnimplementedUserServiceServer
}

func (s *MockUserServiceServer) Register(ctx context.Context, req *proto.RegisterRequest) (*proto.AuthResponse, error) {
	return &proto.AuthResponse{AccessToken: "dummy-access"}, nil
}

func (s *MockUserServiceServer) Login(ctx context.Context, req *proto.LoginRequest) (*proto.AuthResponse, error) {
	return &proto.AuthResponse{AccessToken: "dummy-access"}, nil
}

func (s *MockUserServiceServer) DeleteAccount(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, fmt.Errorf("unauthorized")
}

func (s *MockUserServiceServer) EditAccount(ctx context.Context, req *proto.EditUserRequest) (*proto.UserResponse, error) {
	return nil, fmt.Errorf("unauthorized")
}

func (s *MockUserServiceServer) Logout(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	return nil, fmt.Errorf("unauthorized")
}

func (s *MockUserServiceServer) GetUserById(ctx context.Context, req *proto.UserIdRequest) (*proto.UserResponse, error) {
	return nil, fmt.Errorf("unauthorized")
}

func (s *MockUserServiceServer) GetAllUsers(ctx context.Context, _ *emptypb.Empty) (*proto.UsersResponse, error) {
	return nil, fmt.Errorf("unauthorized")
}

func TestRegister(t *testing.T) {
	s := &MockUserServiceServer{}
	req := &proto.RegisterRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
		RoleId:   1,
	}
	resp, err := s.Register(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "dummy-access", resp.AccessToken)
}

func TestLogin(t *testing.T) {
	s := &MockUserServiceServer{}
	req := &proto.LoginRequest{
		Username: "testuser",
		Password: "password123",
	}
	resp, err := s.Login(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "dummy-access", resp.AccessToken)
}

func TestDeleteAccount(t *testing.T) {
	s := &MockUserServiceServer{}
	_, err := s.DeleteAccount(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
}

func TestEditAccount(t *testing.T) {
	s := &MockUserServiceServer{}
	req := &proto.EditUserRequest{
		Password: "newpassword123",
	}
	_, err := s.EditAccount(context.Background(), req)
	require.Error(t, err)
}

func TestLogout(t *testing.T) {
	s := &MockUserServiceServer{}
	_, err := s.Logout(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
}

func TestGetUserById(t *testing.T) {
	s := &MockUserServiceServer{}
	req := &proto.UserIdRequest{UserId: 1}
	_, err := s.GetUserById(context.Background(), req)
	require.Error(t, err)
}

func TestGetAllUsers(t *testing.T) {
	s := &MockUserServiceServer{}
	_, err := s.GetAllUsers(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
}
