package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/flashbots/mev-boost-relay/common"
)

var ErrQueueURLNotSet = errors.New("queue url not set")

type BuilderSubmissionPayload struct {
	ReceivedAt    time.Time                          `json:"received_at"`
	EligibleAt    time.Time                          `json:"eligible_at"`
	Slot          uint64                             `json:"slot"`
	BuilderPubkey string                             `json:"builder_pubkey"`
	WasSimulated  bool                               `json:"was_simulated"`
	SimError      string                             `json:"sim_error"`
	Submission    common.VersionedSubmitBlockRequest `json:"submission"`
}

type IPayloadQueue interface {
	SendPayload(submission *common.VersionedSubmitBlockRequest, receivedAt, eligibleAt time.Time, wasSimulated bool, validationError error) error
}

type PayloadQueue struct {
	sqsClient   *sqs.SQS
	sqsQueueURL string

	disabled bool
}

func NewPayloadQueue() (*PayloadQueue, error) {
	if os.Getenv("DISABLE_PAYLOAD_QUEUE") == "1" {
		return &PayloadQueue{
			disabled: true,
		}, nil
	}

	sqsQueueURL := os.Getenv("SQS_QUEUE_URL")
	if sqsQueueURL == "" {
		return nil, ErrQueueURLNotSet
	}

	sess, err := session.NewSession()
	if err != nil {
		return nil, err
	}
	if _, err = sess.Config.Credentials.Get(); err != nil {
		return nil, err
	}

	sqsClient := sqs.New(sess)
	return &PayloadQueue{
		sqsClient,
		sqsQueueURL,
		false,
	}, nil
}

func (p *PayloadQueue) SendPayload(submission *common.VersionedSubmitBlockRequest, receivedAt, eligibleAt time.Time, wasSimulated bool, validationError error) error {
	if p.disabled {
		return nil
	}

	submissionInfo, err := common.GetBlockSubmissionInfo(submission)
	if err != nil {
		return err
	}
	slot := submissionInfo.BidTrace.Slot
	epoch := slot / common.SlotsPerEpoch
	// sample 2 out of 20 epochs which is ~10 minutes every 2 hours
	if epoch%20 != 0 && epoch%20 != 1 {
		return nil
	}

	blockHash := submissionInfo.BidTrace.BlockHash
	builderPubkey := submissionInfo.BidTrace.ProposerPubkey.String()
	simErrStr := ""
	if validationError != nil {
		simErrStr = validationError.Error()
	}

	payload := BuilderSubmissionPayload{
		ReceivedAt:    receivedAt,
		EligibleAt:    eligibleAt,
		Slot:          slot,
		BuilderPubkey: builderPubkey,
		WasSimulated:  wasSimulated,
		SimError:      simErrStr,
		Submission:    *submission,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// used to name the payload object
	attributes := map[string]*sqs.MessageAttributeValue{
		"PayloadId": {
			DataType:    aws.String("String"),
			StringValue: aws.String(fmt.Sprintf("%d_%s", slot, blockHash.String())),
		},
	}
	msg := &sqs.SendMessageInput{
		QueueUrl:               &p.sqsQueueURL,
		MessageBody:            aws.String(string(body)),
		MessageDeduplicationId: aws.String(blockHash.String()),
		MessageAttributes:      attributes,
	}

	_, err = p.sqsClient.SendMessage(msg)
	if err != nil {
		return err
	}
	return nil
}
