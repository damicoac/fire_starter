package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// JSONRPCRequest represents a standard JSON-RPC 2.0 Request
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a standard JSON-RPC 2.0 Response
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError represents a JSON-RPC error payload
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ToolDescriptor describes an MCP tool available on a server
type ToolDescriptor struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema,omitempty"`
}

// MCPClient handles JSON-RPC 2.0 communication with an external MCP server
type MCPClient struct {
	reader  io.Reader
	writer  io.Writer
	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]chan *JSONRPCResponse
}

// NewMCPClient initializes a new MCPClient attached to input/output streams
func NewMCPClient(reader io.Reader, writer io.Writer) *MCPClient {
	client := &MCPClient{
		reader:  reader,
		writer:  writer,
		pending: make(map[uint64]chan *JSONRPCResponse),
	}
	go client.listenLoop()
	return client
}

func (c *MCPClient) listenLoop() {
	decoder := json.NewDecoder(c.reader)
	for {
		var resp JSONRPCResponse
		if err := decoder.Decode(&resp); err != nil {
			return
		}
		c.mu.Lock()
		ch, exists := c.pending[resp.ID]
		if exists {
			delete(c.pending, resp.ID)
		}
		c.mu.Unlock()

		if exists && ch != nil {
			ch <- &resp
		}
	}
}

// CallMethod sends a JSON-RPC method invocation request and waits for a response
func (c *MCPClient) CallMethod(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	reqID := atomic.AddUint64(&c.nextID, 1)

	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		rawParams = b
	}

	req := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      reqID,
		Method:  method,
		Params:  rawParams,
	}

	respChan := make(chan *JSONRPCResponse, 1)
	c.mu.Lock()
	c.pending[reqID] = respChan
	c.mu.Unlock()

	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	reqData = append(reqData, '\n')

	c.mu.Lock()
	_, err = c.writer.Write(reqData)
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, reqID)
		c.mu.Unlock()
		return nil, ctx.Err()
	case resp := <-respChan:
		if resp.Error != nil {
			return nil, fmt.Errorf("mcp error (%d): %s", resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	}
}

// ListTools queries the MCP server for available tools (`tools/list`)
func (c *MCPClient) ListTools(ctx context.Context) ([]ToolDescriptor, error) {
	resultRaw, err := c.CallMethod(ctx, "tools/list", nil)
	if err != nil {
		return nil, err
	}

	var payload struct {
		Tools []ToolDescriptor `json:"tools"`
	}
	if err := json.Unmarshal(resultRaw, &payload); err != nil {
		return nil, err
	}

	return payload.Tools, nil
}

// CallTool invokes a specific tool on the MCP server (`tools/call`)
func (c *MCPClient) CallTool(ctx context.Context, name string, arguments map[string]interface{}) (json.RawMessage, error) {
	params := map[string]interface{}{
		"name":      name,
		"arguments": arguments,
	}
	return c.CallMethod(ctx, "tools/call", params)
}
