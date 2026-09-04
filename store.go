package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// Item is a DynamoDB item flattened into plain Go values suitable for JSON
// serialization: S->string, N->json.Number, BOOL->bool, B->base64 string,
// SS/NS/BS->[]string, L->[]any, M->map[string]any, NULL->nil.
type Item map[string]any

// Entry pairs a partition key with its item; the unit of AXFR output.
type Entry struct {
	Key  string
	Item Item
}

// Store retrieves items by their string partition key.
type Store interface {
	Get(ctx context.Context, pk string) (Item, error)
}

// Reader adds enumeration and secondary-index queries (AXFR / GSI lookups).
type Reader interface {
	Store
	// List streams every item in the table, calling fn once per page.
	List(ctx context.Context, fn func([]Entry) error) error
	// QueryIndex queries a configured GSI: index is the DNS-facing index name,
	// value the equality key. Returns matching items in key order.
	QueryIndex(ctx context.Context, index, value string) ([]Entry, error)
}

// Writer adds the RFC 2136 update path (PutItem / DeleteItem).
type Writer interface {
	Put(ctx context.Context, pk string, item Item) error
	Delete(ctx context.Context, pk string) error
}

// FullStore is everything a fully operational ContractDB needs from storage.
type FullStore interface {
	Reader
	Writer
}

type dynamoStore struct {
	client     *dynamodb.Client
	table      string
	pkAttr     string
	consistent bool
	gsiAttrs   map[string]string // DNS-facing index name -> GSI partition key attribute
}

func NewDynamoStore(client *dynamodb.Client, table, pkAttr string, consistent bool) Store {
	return NewFullDynamoStore(client, table, pkAttr, consistent, nil)
}

// NewFullDynamoStore builds a store with write and enumeration support.
// gsiAttrs maps DNS-facing index names (e.g. "gsi-email") to the GSI's
// partition key attribute in DynamoDB (e.g. "email").
func NewFullDynamoStore(client *dynamodb.Client, table, pkAttr string, consistent bool, gsiAttrs map[string]string) FullStore {
	return &dynamoStore{client: client, table: table, pkAttr: pkAttr, consistent: consistent, gsiAttrs: gsiAttrs}
}

func (s *dynamoStore) Get(ctx context.Context, pk string) (Item, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName:      &s.table,
		Key:            map[string]types.AttributeValue{s.pkAttr: &types.AttributeValueMemberS{Value: pk}},
		ConsistentRead: &s.consistent,
	})
	if err != nil {
		return nil, fmt.Errorf("dynamodb GetItem: %w", err)
	}
	if out.Item == nil {
		return nil, nil
	}
	item := make(Item, len(out.Item))
	for k, v := range out.Item {
		flat, err := flatten(v)
		if err != nil {
			return nil, fmt.Errorf("attribute %q: %w", k, err)
		}
		item[k] = flat
	}
	return item, nil
}

func (s *dynamoStore) Put(ctx context.Context, pk string, item Item) error {
	av := make(map[string]types.AttributeValue, len(item)+1)
	av[s.pkAttr] = &types.AttributeValueMemberS{Value: pk}
	for k, v := range item {
		if k == s.pkAttr {
			continue
		}
		val, err := unflatten(v)
		if err != nil {
			return fmt.Errorf("attribute %q: %w", k, err)
		}
		av[k] = val
	}
	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: &s.table, Item: av})
	if err != nil {
		return fmt.Errorf("dynamodb PutItem: %w", err)
	}
	return nil
}

func (s *dynamoStore) Delete(ctx context.Context, pk string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: &s.table,
		Key:       map[string]types.AttributeValue{s.pkAttr: &types.AttributeValueMemberS{Value: pk}},
	})
	if err != nil {
		return fmt.Errorf("dynamodb DeleteItem: %w", err)
	}
	return nil
}

func (s *dynamoStore) List(ctx context.Context, fn func([]Entry) error) error {
	pager := dynamodb.NewScanPaginator(s.client, &dynamodb.ScanInput{TableName: &s.table})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("dynamodb Scan: %w", err)
		}
		entries := make([]Entry, 0, len(page.Items))
		for _, av := range page.Items {
			pkAv, ok := av[s.pkAttr]
			if !ok {
				continue
			}
			sPtr, ok := pkAv.(*types.AttributeValueMemberS)
			if !ok {
				continue
			}
			item := make(Item, len(av))
			for k, v := range av {
				flat, err := flatten(v)
				if err != nil {
					return fmt.Errorf("attribute %q: %w", k, err)
				}
				item[k] = flat
			}
			entries = append(entries, Entry{Key: sPtr.Value, Item: item})
		}
		if err := fn(entries); err != nil {
			return err
		}
	}
	return nil
}

func (s *dynamoStore) QueryIndex(ctx context.Context, index, value string) ([]Entry, error) {
	attr, ok := s.gsiAttrs[index]
	if !ok {
		return nil, fmt.Errorf("unknown index %q", index)
	}
	pager := dynamodb.NewQueryPaginator(s.client, &dynamodb.QueryInput{
		TableName:                 &s.table,
		IndexName:                 &index,
		KeyConditionExpression:    aws.String("#a = :v"),
		ExpressionAttributeNames:  map[string]string{"#a": attr},
		ExpressionAttributeValues: map[string]types.AttributeValue{":v": &types.AttributeValueMemberS{Value: value}},
	})
	var out []Entry
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("dynamodb Query(%s): %w", index, err)
		}
		for _, av := range page.Items {
			item := make(Item, len(av))
			var key string
			for k, v := range av {
				flat, err := flatten(v)
				if err != nil {
					return nil, fmt.Errorf("attribute %q: %w", k, err)
				}
				item[k] = flat
				if k == s.pkAttr {
					key = flat.(string)
				}
			}
			out = append(out, Entry{Key: key, Item: item})
		}
	}
	return out, nil
}

func flatten(v types.AttributeValue) (any, error) {
	switch t := v.(type) {
	case *types.AttributeValueMemberS:
		return t.Value, nil
	case *types.AttributeValueMemberN:
		return jsonNumber(t.Value)
	case *types.AttributeValueMemberB:
		return base64.StdEncoding.EncodeToString(t.Value), nil
	case *types.AttributeValueMemberBOOL:
		return t.Value, nil
	case *types.AttributeValueMemberNULL:
		return nil, nil
	case *types.AttributeValueMemberSS:
		return append([]string{}, t.Value...), nil
	case *types.AttributeValueMemberNS:
		out := make([]any, len(t.Value))
		for i, n := range t.Value {
			num, err := jsonNumber(n)
			if err != nil {
				return nil, err
			}
			out[i] = num
		}
		return out, nil
	case *types.AttributeValueMemberBS:
		out := make([]string, len(t.Value))
		for i, b := range t.Value {
			out[i] = base64.StdEncoding.EncodeToString(b)
		}
		return out, nil
	case *types.AttributeValueMemberL:
		out := make([]any, len(t.Value))
		for i, e := range t.Value {
			flat, err := flatten(e)
			if err != nil {
				return nil, err
			}
			out[i] = flat
		}
		return out, nil
	case *types.AttributeValueMemberM:
		out := make(map[string]any, len(t.Value))
		for k, e := range t.Value {
			flat, err := flatten(e)
			if err != nil {
				return nil, fmt.Errorf("attribute %q: %w", k, err)
			}
			out[k] = flat
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported attribute value type %T", v)
	}
}

func jsonNumber(n string) (any, error) {
	_, err := strconv.ParseFloat(n, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid number %q", n)
	}
	return json.Number(n), nil
}

// unflatten converts plain Go values (as produced by flatten) back into
// DynamoDB attribute values for the write path.
func unflatten(v any) (types.AttributeValue, error) {
	switch t := v.(type) {
	case nil:
		return &types.AttributeValueMemberNULL{Value: true}, nil
	case string:
		return &types.AttributeValueMemberS{Value: t}, nil
	case bool:
		return &types.AttributeValueMemberBOOL{Value: t}, nil
	case float64:
		return &types.AttributeValueMemberN{Value: strconv.FormatFloat(t, 'f', -1, 64)}, nil
	case json.Number:
		return &types.AttributeValueMemberN{Value: t.String()}, nil
	case []string:
		return &types.AttributeValueMemberSS{Value: append([]string{}, t...)}, nil
	case []any:
		l := make([]types.AttributeValue, len(t))
		for i, e := range t {
			val, err := unflatten(e)
			if err != nil {
				return nil, err
			}
			l[i] = val
		}
		return &types.AttributeValueMemberL{Value: l}, nil
	case map[string]any:
		m := make(map[string]types.AttributeValue, len(t))
		for k, e := range t {
			val, err := unflatten(e)
			if err != nil {
				return nil, fmt.Errorf("attribute %q: %w", k, err)
			}
			m[k] = val
		}
		return &types.AttributeValueMemberM{Value: m}, nil
	default:
		return nil, fmt.Errorf("unsupported value type %T", v)
	}
}
