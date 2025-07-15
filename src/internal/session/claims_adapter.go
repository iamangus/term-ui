package session

func (c *Claims) GetUsername() string {
	return c.Username
}

func (c *Claims) GetEmail() string {
	return c.Email
}