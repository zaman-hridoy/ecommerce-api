package user

type User struct {
	ID				string `json:"id"`
	Name			string `json:"name"`
	Email			string `json:"email"`
	PasswordHash	string `json:"-"`
	CreatedAt		string `json:"created_at"`
	UpdatedAt		string `json:"updated_at"`
}


