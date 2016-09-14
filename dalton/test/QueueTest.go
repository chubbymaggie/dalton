package main

import (
	"dalton/engine"
	"fmt"
)

func main() {

	q := engine.NewQueue()
	i := 0
	for i < 20 {

		q.Push(i+1)
		i++
	}

	//now pulling
	fmt.Println(q.Len())

	i = 0

	for i < 20 {

		fmt.Println(q.Poll())
		i++
	}
	fmt.Println(q.Len())
}
