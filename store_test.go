package main

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

func TestFlattenNumberPreservesDynamoDBPrecision(t *testing.T) {
	const original = "12345678901234567890123456789012345678"
	got, err := flatten(&types.AttributeValueMemberN{Value: original})
	if err != nil {
		t.Fatal(err)
	}
	n, ok := got.(json.Number)
	if !ok {
		t.Fatalf("flatten number type = %T, want json.Number", got)
	}
	if n.String() != original {
		t.Fatalf("flatten number = %s, want %s", n, original)
	}
	encoded, err := json.Marshal(Item{"n": n})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"n":12345678901234567890123456789012345678}` {
		t.Fatalf("JSON = %s", encoded)
	}
}
