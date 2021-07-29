package paths

import (
	"fmt"

	"www.velocidex.com/golang/velociraptor/constants"
	"www.velocidex.com/golang/velociraptor/utils"
)

type UserPathManager struct {
	Name string
}

func (self UserPathManager) Path() string {
	return constants.USER_URN + self.Name
}

func (self UserPathManager) Directory() string {
	return constants.USER_URN
}

func (self UserPathManager) ACL() string {
	return fmt.Sprintf("/acl/%v.json", self.Name)
}

func (self UserPathManager) GUIOptions() string {
	return constants.USER_URN + "/gui/" + self.Name + ".json"
}

func (self UserPathManager) MRU() string {
	return utils.JoinComponents([]string{constants.USER_URN, self.Name}, "/")
}
