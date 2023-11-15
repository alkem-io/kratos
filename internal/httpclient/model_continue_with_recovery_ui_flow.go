/*
 * Ory Identities API
 *
 * This is the API specification for Ory Identities with features such as registration, login, recovery, account verification, profile settings, password reset, identity management, session management, email and sms delivery, and more.
 *
 * API version:
 * Contact: office@ory.sh
 */

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"encoding/json"
)

// ContinueWithRecoveryUiFlow struct for ContinueWithRecoveryUiFlow
type ContinueWithRecoveryUiFlow struct {
	// The ID of the recovery flow
	Id string `json:"id"`
	// The URL of the recovery flow
	Url *string `json:"url,omitempty"`
}

// NewContinueWithRecoveryUiFlow instantiates a new ContinueWithRecoveryUiFlow object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewContinueWithRecoveryUiFlow(id string) *ContinueWithRecoveryUiFlow {
	this := ContinueWithRecoveryUiFlow{}
	this.Id = id
	return &this
}

// NewContinueWithRecoveryUiFlowWithDefaults instantiates a new ContinueWithRecoveryUiFlow object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewContinueWithRecoveryUiFlowWithDefaults() *ContinueWithRecoveryUiFlow {
	this := ContinueWithRecoveryUiFlow{}
	return &this
}

// GetId returns the Id field value
func (o *ContinueWithRecoveryUiFlow) GetId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Id
}

// GetIdOk returns a tuple with the Id field value
// and a boolean to check if the value has been set.
func (o *ContinueWithRecoveryUiFlow) GetIdOk() (*string, bool) {
	if o == nil {
		return nil, false
	}
	return &o.Id, true
}

// SetId sets field value
func (o *ContinueWithRecoveryUiFlow) SetId(v string) {
	o.Id = v
}

// GetUrl returns the Url field value if set, zero value otherwise.
func (o *ContinueWithRecoveryUiFlow) GetUrl() string {
	if o == nil || o.Url == nil {
		var ret string
		return ret
	}
	return *o.Url
}

// GetUrlOk returns a tuple with the Url field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ContinueWithRecoveryUiFlow) GetUrlOk() (*string, bool) {
	if o == nil || o.Url == nil {
		return nil, false
	}
	return o.Url, true
}

// HasUrl returns a boolean if a field has been set.
func (o *ContinueWithRecoveryUiFlow) HasUrl() bool {
	if o != nil && o.Url != nil {
		return true
	}

	return false
}

// SetUrl gets a reference to the given string and assigns it to the Url field.
func (o *ContinueWithRecoveryUiFlow) SetUrl(v string) {
	o.Url = &v
}

func (o ContinueWithRecoveryUiFlow) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if true {
		toSerialize["id"] = o.Id
	}
	if o.Url != nil {
		toSerialize["url"] = o.Url
	}
	return json.Marshal(toSerialize)
}

type NullableContinueWithRecoveryUiFlow struct {
	value *ContinueWithRecoveryUiFlow
	isSet bool
}

func (v NullableContinueWithRecoveryUiFlow) Get() *ContinueWithRecoveryUiFlow {
	return v.value
}

func (v *NullableContinueWithRecoveryUiFlow) Set(val *ContinueWithRecoveryUiFlow) {
	v.value = val
	v.isSet = true
}

func (v NullableContinueWithRecoveryUiFlow) IsSet() bool {
	return v.isSet
}

func (v *NullableContinueWithRecoveryUiFlow) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableContinueWithRecoveryUiFlow(val *ContinueWithRecoveryUiFlow) *NullableContinueWithRecoveryUiFlow {
	return &NullableContinueWithRecoveryUiFlow{value: val, isSet: true}
}

func (v NullableContinueWithRecoveryUiFlow) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableContinueWithRecoveryUiFlow) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
