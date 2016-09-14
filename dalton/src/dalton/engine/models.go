package engine

import (
	"fmt"
	"sync"
)

type DaltonNode struct {

	ScriptFileName string  // the script file name to execute
	Children []DaltonNode //the dependencies of the current script
	executed bool          // if the current script has been executed or not yet
}

func (node *DaltonNode) IsExecuted() bool {
	return node.executed
}



func (node *DaltonNode) GetDepsSize () int {

	return len(node.Children)
}


func (node *DaltonNode) HasChildren() bool {

	if len(node.Children) > 0 {
		return true
	}else{

		return false
	}
}

func (node *DaltonNode) GetChildren() ([]DaltonNode,error){

	if node.HasChildren() {
		return node.Children, nil
	}
	return nil , fmt.Errorf("Current Node has no Children")
}


/////////////////////////////////////////////////////Queue implementation for Dalton Engine //////////////////////////////////////////////


type queuenode struct {
	data interface{}
	next *queuenode
}

//	A go-routine safe FIFO (first in first out) data stucture.
type DaltonQueue struct {
	head  *queuenode
	tail  *queuenode
	count int
	lock  *sync.Mutex
}

//	Creates a new pointer to a new queue.
func NewQueue() *DaltonQueue {
	q := &DaltonQueue{}
	q.lock = &sync.Mutex{}
	return q
}

//	Returns the number of elements in the queue (i.e. size/length)
//	go-routine safe.
func (q *DaltonQueue) Len() int {
	q.lock.Lock()
	defer q.lock.Unlock()
	return q.count
}

//	Pushes/inserts a value at the end/tail of the queue.
//	Note: this function does mutate the queue.
//	go-routine safe.
func (q *DaltonQueue) Push(item interface{}) {
	q.lock.Lock()
	defer q.lock.Unlock()

	n := &queuenode{data: item}

	if q.tail == nil {
		q.tail = n
		q.head = n
	} else {
		q.tail.next = n
		q.tail = n
	}
	q.count++
}

//	Returns the value at the front of the queue.
//	i.e. the oldest value in the queue.
//	Note: this function does mutate the queue.
//	go-routine safe.
func (q *DaltonQueue) Poll() interface{} {
	q.lock.Lock()
	defer q.lock.Unlock()

	if q.head == nil {
		return nil
	}

	n := q.head
	q.head = n.next

	if q.head == nil {
		q.tail = nil
	}
	q.count--

	return n.data
}

//	Returns a read value at the front of the queue.
//	i.e. the oldest value in the queue.
//	Note: this function does NOT mutate the queue.
//	go-routine safe.
func (q *DaltonQueue) Peek() interface{} {
	q.lock.Lock()
	defer q.lock.Unlock()

	n := q.head
	if n == nil {
		return nil
	}

	return n.data
}



