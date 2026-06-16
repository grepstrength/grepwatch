package queue

import "github.com/grepstrength/grepwatch/model"

const Size = 500 

type Queue struct { //this wraps a channel in a struct so methods can be attached to it
	ch chan model.Package //ch is lowercase, nothing outside this package touches the channel directly
}

func New() *Queue { //writing Queue{} directly gets a nil channel and a deadlock on the first Push
	return &Queue{
		ch: make(chan model.Package, Size), //the make call is what creates the buffered channel, which Size being the capacity
	}
}

func (q *Queue) Push(pkg model.Package) {
	q.ch <- pkg //this sends a package into the channel... if its full (500 packages waiting) it slows the crawlers down
}


func (q *Queue) Pop() <-chan model.Package { //the "<-chan" return type means whoever calls this gets a receive only channel. it can be read from but cannot be written to
	return q.ch //returns the channel itself
}

func (q *Queue) Len() int {
	return len(q.ch) //this returns how many package are sitting in the queue, this is used for health checks
}