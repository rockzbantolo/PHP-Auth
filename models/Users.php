<?php
namespace Svm\Models;

use DateTime;

class Users
{
    public ?int $user_id = null;
    public ?int $role_id = null;
    public ?int $job_id = null;
    public ?string $username = null;
    public ?string $email = null;
    public ?string $password = null;
    public ?string $secret_pass = null;
    public ?string $first_name = null;
    public ?string $last_name = null;
    public ?string $contact = null;
    public ?string $address = null;
    public ?string $avatar = null;
    public ?string $last_ip_address = null;
    public ?DateTime $last_login = null;
    public ?DateTime $last_logout = null;
    public int $failed_attempts = 0;
    public ?DateTime $lock_until = null;
    public bool $is_two_factor = false;
    public bool $is_online = false;
    public bool $is_approved = false;
    public bool $is_active = true;
    public ?DateTime $updated_at = null;
    public ?DateTime $created_at = null;
    public ?DateTime $deleted_at = null;

    public function __construct(array $data = [])
    {
         foreach ($data as $key => $value) {
            if (!property_exists($this, $key)) continue;

            // Handle datetime fields
            if (in_array($key, ['last_login', 'last_logout', 'lock_until', 'updated_at', 'created_at', 'deleted_at']) && $value !== null) {
                $this->$key = new DateTime($value);
            }
            // Automatically hash the password if provided
            elseif ($key === 'password' && $value !== null) {
                $this->password = password_hash($value, PASSWORD_BCRYPT);
            }
            else {
                $this->$key = $value;
            }
        }
    }

    // Optional: helper to get array for insert/update
    public function toArray(): array
    {
        $data = get_object_vars($this);

        // Convert DateTime objects to string
        foreach ($data as $key => $value) {
            if ($value instanceof DateTime) {
                $data[$key] = $value->format('Y-m-d H:i:s');
            }
        }

        return $data;
    }

    public function validate(): array
    {
        $errors = [];
        if (empty($this->username)) {
            $errors[] = "Username is required";
        }
        if (!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Invalid email format";
        }
        return $errors;
    }

    public function getFullName(): string
    {
        return trim($this->first_name . ' ' . $this->last_name);
    }

    public function softDelete(): void
    {
        $this->deleted_at = new DateTime();
        $this->is_active = false;
    }

    public function toPublicArray(): array
    {
        $data = $this->toArray();
        unset($data['password_hash'], $data['secret_pass']);
        return $data;
    }

}
