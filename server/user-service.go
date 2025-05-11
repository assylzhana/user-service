package server

import (
	"context"
	"user-service-go/config"
	"user-service-go/utils"

	"user-service-go/proto"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type UserServiceServer struct {
	proto.UnimplementedUserServiceServer
}

func (s *UserServiceServer) Register(ctx context.Context, req *proto.RegisterRequest) (*proto.AuthResponse, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Password hashing failed")
	}

	var userID int
	err = config.DB.QueryRow(
		"INSERT INTO users (username, password, email, role_id) VALUES ($1, $2, $3, $4) RETURNING id",
		req.Username, string(hashedPassword), req.Email, req.RoleId,
	).Scan(&userID)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "Registration failed: %v", err)
	}

	var roleName string
	err = config.DB.QueryRow("SELECT name FROM roles WHERE id=$1", req.RoleId).Scan(&roleName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to retrieve role name")
	}

	token, _ := utils.GenerateJWT(userID, roleName)
	return &proto.AuthResponse{AccessToken: token}, nil
}

func (s *UserServiceServer) Login(ctx context.Context, req *proto.LoginRequest) (*proto.AuthResponse, error) {
	var userID int
	var hashedPassword string
	var roleID int

	err := config.DB.QueryRow(
		"SELECT id, password, role_id FROM users WHERE username=$1", req.Username,
	).Scan(&userID, &hashedPassword, &roleID)

	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid credentials")
	}

	var roleName string
	err = config.DB.QueryRow("SELECT name FROM roles WHERE id=$1", roleID).Scan(&roleName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to retrieve role name")
	}

	token, _ := utils.GenerateJWT(userID, roleName)
	return &proto.AuthResponse{AccessToken: token}, nil
}

func (s *UserServiceServer) DeleteAccount(ctx context.Context, req *proto.UserIdRequest) (*proto.MessageResponse, error) {
	_, err := config.DB.Exec("DELETE FROM users WHERE id=$1", req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Deletion failed")
	}
	return &proto.MessageResponse{Message: "Account deleted"}, nil
}

func (s *UserServiceServer) EditAccount(ctx context.Context, req *proto.EditUserRequest) (*proto.MessageResponse, error) {
	_, err := config.DB.Exec(
		"UPDATE users SET username=$1, email=$2, role_id=$3 WHERE id=$4",
		req.Username, req.Email, req.RoleId, req.UserId,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Update failed")
	}
	return &proto.MessageResponse{Message: "Account updated"}, nil
}
