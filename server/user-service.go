package server

import (
	"context"
	"log"
	"strings"
	"user-service-go/config"
	"user-service-go/proto"
	"user-service-go/utils"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type UserServiceServer struct {
	proto.UnimplementedUserServiceServer
}

func extractAndValidateToken(ctx context.Context) (*utils.Claims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "Missing metadata")
	}
	authHeader := md["authorization"]
	if len(authHeader) == 0 {
		return nil, status.Error(codes.Unauthenticated, "Authorization token not provided")
	}
	token := strings.TrimPrefix(authHeader[0], "Bearer ")
	claims, err := utils.ValidateJWT(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "Invalid token")
	}
	return claims, nil
}

func (s *UserServiceServer) Register(ctx context.Context, req *proto.RegisterRequest) (*proto.AuthResponse, error) {
	if len(req.Password) < 8 {
		return nil, status.Errorf(codes.InvalidArgument, "Password must be at least 8 characters long")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Password hashing failed")
	}

	var userID int
	err = config.DB.QueryRow(
		"INSERT INTO users (username, email, password, role_id) VALUES ($1, $2, $3, $4) RETURNING id",
		req.Username, req.Email, string(hashedPassword), req.RoleId,
	).Scan(&userID)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "Registration failed: %v", err)
	}

	var roleName string
	err = config.DB.QueryRow("SELECT name FROM roles WHERE id=$1", req.RoleId).Scan(&roleName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to retrieve role name")
	}

	go log.Printf("[REGISTER] New user: ID=%d, Username=%s, Role=%s", userID, req.Username, roleName)

	token, _ := utils.GenerateJWT(userID, roleName)
	return &proto.AuthResponse{AccessToken: token}, nil
}

func (s *UserServiceServer) Login(ctx context.Context, req *proto.LoginRequest) (*proto.AuthResponse, error) {
	var userID int
	var hashedPassword string
	var roleID int

	err := config.DB.QueryRow("SELECT id, password, role_id FROM users WHERE username=$1", req.Username).
		Scan(&userID, &hashedPassword, &roleID)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)) != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid credentials")
	}

	var roleName string
	err = config.DB.QueryRow("SELECT name FROM roles WHERE id=$1", roleID).Scan(&roleName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to retrieve role name")
	}

	go log.Printf("[LOGIN] User ID=%d, Username=%s", userID, req.Username)

	token, _ := utils.GenerateJWT(userID, roleName)
	return &proto.AuthResponse{AccessToken: token}, nil
}

func (s *UserServiceServer) DeleteAccount(ctx context.Context, _ *emptypb.Empty) (*proto.MessageResponse, error) {
	claims, err := extractAndValidateToken(ctx)
	if err != nil {
		return nil, err
	}

	_, err = config.DB.Exec("DELETE FROM users WHERE id=$1", claims.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Deletion failed")
	}

	go log.Printf("[DELETE] User ID=%d deleted", claims.UserID)
	return &proto.MessageResponse{Message: "Account deleted"}, nil
}

func (s *UserServiceServer) EditAccount(ctx context.Context, req *proto.EditUserRequest) (*proto.MessageResponse, error) {
	claims, err := extractAndValidateToken(ctx)
	if err != nil {
		return nil, err
	}

	log.Printf("Password received: '%s'", req.Password)

	if len(strings.TrimSpace(req.Password)) < 8 {
		return nil, status.Errorf(codes.InvalidArgument, "Password must be at least 8 characters long")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to hash password")
	}

	_, err = config.DB.Exec("UPDATE users SET password=$1 WHERE id=$2", string(hashedPassword), claims.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to update password: %v", err)
	}

	log.Printf("[EDIT] Password updated for User ID=%d", claims.UserID)
	return &proto.MessageResponse{Message: "Password updated"}, nil
}

func (s *UserServiceServer) Logout(ctx context.Context, _ *emptypb.Empty) (*proto.MessageResponse, error) {
	claims, err := extractAndValidateToken(ctx)
	if err != nil {
		return nil, err
	}

	go log.Printf("[LOGOUT] User ID=%d logged out", claims.UserID)
	return &proto.MessageResponse{Message: "User logged out"}, nil
}

func (s *UserServiceServer) GetUserById(ctx context.Context, req *proto.UserIdRequest) (*proto.UserResponse, error) {
	claims, err := extractAndValidateToken(ctx)
	if err != nil {
		return nil, err
	}

	if int32(claims.UserID) != req.UserId && claims.Role != "admin" {
		return nil, status.Errorf(codes.PermissionDenied, "Not authorized to view this user")
	}

	var user proto.UserResponse
	err = config.DB.QueryRow("SELECT id, username, email, role_id FROM users WHERE id=$1", req.UserId).
		Scan(&user.Id, &user.Username, &user.Email, &user.RoleId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "User not found")
	}
	return &user, nil
}

func (s *UserServiceServer) GetAllUsers(ctx context.Context, _ *emptypb.Empty) (*proto.UsersResponse, error) {
	claims, err := extractAndValidateToken(ctx)
	if err != nil {
		return nil, err
	}

	if claims.Role != "admin" {
		return nil, status.Errorf(codes.PermissionDenied, "Only admin can view all users")
	}

	rows, err := config.DB.Query("SELECT id, username, email, role_id FROM users")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to fetch users")
	}
	defer rows.Close()

	var users []*proto.UserResponse
	for rows.Next() {
		var user proto.UserResponse
		if err := rows.Scan(&user.Id, &user.Username, &user.Email, &user.RoleId); err != nil {
			return nil, status.Errorf(codes.Internal, "Failed to read user row")
		}
		users = append(users, &user)
	}

	return &proto.UsersResponse{Users: users}, nil
}
