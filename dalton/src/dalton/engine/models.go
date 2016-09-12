package engine

import "fmt"

type Node struct {

	ScriptFileName string // the script file name to execute
	Children []*Node //the dependencies of the current script
	executed bool // if the current script has been executed or not yet
}

func (node *Node) IsExecuted() bool {
	return node.executed
}

func (node *Node) AddDeps(v ...*Node) error{
	node.Children = append(node.Children,v...)
	return nil
}

func (node *Node) AddStringAsDep(scriptFileNames...string) error {

	if len(scriptFileNames) <= 0 {
		return fmt.Errorf("Dependencies should not be empty")
	}

	deps := []*Node{}

	for _ , dep := range scriptFileNames {

		//create a new dependency
		node := &Node{ScriptFileName:dep}
		deps = append(deps,node)
	}
	return node.AddDeps(deps)
}

func (node *Node) GetDepsSize () int {

	return len(node.Children)
}


func (node *Node) HasChildren() bool {

	if len(node.Children) > 0 {
		return true
	}else{

		return false
	}
}

func (node *Node) GetChildren() ([]*Node,error){

	if node.HasChildren() {
		return node.Children, nil
	}
	return nil , fmt.Errorf("Current Node has no Children")
}




