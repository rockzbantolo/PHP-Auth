<?php
namespace Svm\Controllers;

use Svm\Services\AuthSvc;

class AuthCtrl
{
    private AuthSvc $model;

    public function __construct()
    {
        $this->model = new AuthSvc();
    }

    public function getAllUsers()
    {
        $page = $_GET['page'] ?? 1;
        $limit = $_GET['limit'] ?? 10;
        $this->model->findAllUsers($page, $limit);
    }

    public function getUserDetails($id)
    {
        $this->model->findUserById($id);
    }

    public function registerUser(array $payload)
    {
        $this->model->createUser($payload);
    }

    public function updateUserDetails(int $id, array $payload)
    {
        $this->model->updateUserById($id, $payload);
    }

    public function deleteUserDetails($user)
    {
        $this->model->deleteUserById($user);
    }

    public function login($user)
    {
        $this->model->loginUser($user);
    }

    public function logout($user)
    {
        $this->model->logoutUser($user);
    }

    public function refreshToken($reftoken)
    {
        $this->model->refreshUserToken($reftoken);
    }

    public function requestOTP($otp)
    {
        $this->model->requestUserOTP($otp);
    }

    public function verifyOTP($otp)
    {
        $this->model->verifyUserOTP($otp);
    }

    public function getUserActivity($userId)
    {  
        $page = $_GET['page'] ?? 1;
        $limit = $_GET['limit'] ?? 50;
    }
}
