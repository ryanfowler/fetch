package ws

import (
	"context"
	"sync/atomic"

	"github.com/coder/websocket"
	"github.com/ryanfowler/fetch/internal/core"
)

// wsMessage is the unit passed from the connection reader to the interactive
// renderer. Keeping the size with the value lets messageQueue account for
// bytes rather than only counting messages.
type wsMessage struct {
	typ  websocket.MessageType
	data []byte
	err  error
}

const (
	// A queue may hold at most two maximum-sized messages. The reader blocks
	// when this budget is exhausted, which applies backpressure to the peer
	// instead of retaining an unbounded flood in memory.
	interactiveQueueBytes = 2 * core.MaxWebSocketMessageBytes
	interactiveQueueChunk = 64 * 1024
)

// messageQueue is a bounded producer/consumer queue. The token channel is a
// byte budget; the item channel only limits the number of wakeups and does not
// define the memory bound.
type messageQueue struct {
	items  chan wsMessage
	tokens chan struct{}
	used   atomic.Int64
}

func newMessageQueue() *messageQueue {
	chunks := int((interactiveQueueBytes + interactiveQueueChunk - 1) / interactiveQueueChunk)
	tokens := make(chan struct{}, chunks)
	for range chunks {
		tokens <- struct{}{}
	}
	return &messageQueue{
		items:  make(chan wsMessage, 8),
		tokens: tokens,
	}
}

func (q *messageQueue) C() <-chan wsMessage { return q.items }

func (q *messageQueue) push(ctx context.Context, msg wsMessage) error {
	if int64(len(msg.data)) > core.MaxWebSocketMessageBytes {
		return core.LimitError{Subsystem: "WebSocket incoming message", Limit: core.MaxWebSocketMessageBytes}
	}
	n := queueChunks(len(msg.data))
	acquired := 0
	for acquired < n {
		select {
		case <-q.tokens:
			acquired++
			q.used.Add(interactiveQueueChunk)
		case <-ctx.Done():
			q.release(acquired)
			return ctx.Err()
		}
	}

	select {
	case q.items <- msg:
		return nil
	case <-ctx.Done():
		q.release(acquired)
		return ctx.Err()
	}
}

func (q *messageQueue) pop() wsMessage {
	msg := <-q.items
	q.release(queueChunks(len(msg.data)))
	return msg
}

func (q *messageQueue) release(n int) {
	for range n {
		q.tokens <- struct{}{}
		q.used.Add(-interactiveQueueChunk)
	}
}

func (q *messageQueue) bytes() int64 { return q.used.Load() }

func queueChunks(size int) int {
	if size <= 0 {
		return 1
	}
	return (size + interactiveQueueChunk - 1) / interactiveQueueChunk
}
