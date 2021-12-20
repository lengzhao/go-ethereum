package miner

import "encoding/hex"

var tokenCode []byte

func init() {
	tokenCode, _ = hex.DecodeString("608060405234801561001057600080fd5b50600436106100b45760003560e01c806370a082311161007157806370a08231146101a357806395d89b41146101d3578063a0712d68146101f1578063a457c2d71461020d578063a9059cbb1461023d578063dd62ed3e1461026d576100b4565b806306fdde03146100b9578063095ea7b3146100d757806318160ddd1461010757806323b872dd14610125578063313ce567146101555780633950935114610173575b600080fd5b6100c161029d565b6040516100ce9190610dd2565b60405180910390f35b6100f160048036038101906100ec9190610e8d565b61032f565b6040516100fe9190610ee8565b60405180910390f35b61010f61034d565b60405161011c9190610f12565b60405180910390f35b61013f600480360381019061013a9190610f2d565b610357565b60405161014c9190610ee8565b60405180910390f35b61015d61044f565b60405161016a9190610f9c565b60405180910390f35b61018d60048036038101906101889190610e8d565b610458565b60405161019a9190610ee8565b60405180910390f35b6101bd60048036038101906101b89190610fb7565b610504565b6040516101ca9190610f12565b60405180910390f35b6101db61054c565b6040516101e89190610dd2565b60405180910390f35b61020b60048036038101906102069190610fe4565b6105de565b005b61022760048036038101906102229190610e8d565b6105eb565b6040516102349190610ee8565b60405180910390f35b61025760048036038101906102529190610e8d565b6106d6565b6040516102649190610ee8565b60405180910390f35b61028760048036038101906102829190611011565b6106f4565b6040516102949190610f12565b60405180910390f35b6060600380546102ac90611080565b80601f01602080910402602001604051908101604052809291908181526020018280546102d890611080565b80156103255780601f106102fa57610100808354040283529160200191610325565b820191906000526020600020905b81548152906001019060200180831161030857829003601f168201915b5050505050905090565b600061034361033c61077b565b8484610783565b6001905092915050565b6000600254905090565b600061036484848461094e565b6000600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006103af61077b565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205490508281101561042f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161042690611124565b60405180910390fd5b6104438561043b61077b565b858403610783565b60019150509392505050565b60006012905090565b60006104fa61046561077b565b84846001600061047361077b565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008873ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546104f59190611173565b610783565b6001905092915050565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b60606004805461055b90611080565b80601f016020809104026020016040519081016040528092919081815260200182805461058790611080565b80156105d45780601f106105a9576101008083540402835291602001916105d4565b820191906000526020600020905b8154815290600101906020018083116105b757829003601f168201915b5050505050905090565b6105e83382610bcf565b50565b600080600160006105fa61077b565b73ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050828110156106b7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016106ae9061123b565b60405180910390fd5b6106cb6106c261077b565b85858403610783565b600191505092915050565b60006106ea6106e361077b565b848461094e565b6001905092915050565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b600033905090565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1614156107f3576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016107ea906112cd565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415610863576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161085a9061135f565b60405180910390fd5b80600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925836040516109419190610f12565b60405180910390a3505050565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1614156109be576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016109b5906113f1565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415610a2e576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610a2590611483565b60405180910390fd5b610a39838383610d2f565b60008060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905081811015610abf576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610ab690611515565b60405180910390fd5b8181036000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254610b529190611173565b925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef84604051610bb69190610f12565b60405180910390a3610bc9848484610d34565b50505050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415610c3f576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610c3690611581565b60405180910390fd5b610c4b60008383610d2f565b8060026000828254610c5d9190611173565b92505081905550806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254610cb29190611173565b925050819055508173ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef83604051610d179190610f12565b60405180910390a3610d2b60008383610d34565b5050565b505050565b505050565b600081519050919050565b600082825260208201905092915050565b60005b83811015610d73578082015181840152602081019050610d58565b83811115610d82576000848401525b50505050565b6000601f19601f8301169050919050565b6000610da482610d39565b610dae8185610d44565b9350610dbe818560208601610d55565b610dc781610d88565b840191505092915050565b60006020820190508181036000830152610dec8184610d99565b905092915050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000610e2482610df9565b9050919050565b610e3481610e19565b8114610e3f57600080fd5b50565b600081359050610e5181610e2b565b92915050565b6000819050919050565b610e6a81610e57565b8114610e7557600080fd5b50565b600081359050610e8781610e61565b92915050565b60008060408385031215610ea457610ea3610df4565b5b6000610eb285828601610e42565b9250506020610ec385828601610e78565b9150509250929050565b60008115159050919050565b610ee281610ecd565b82525050565b6000602082019050610efd6000830184610ed9565b92915050565b610f0c81610e57565b82525050565b6000602082019050610f276000830184610f03565b92915050565b600080600060608486031215610f4657610f45610df4565b5b6000610f5486828701610e42565b9350506020610f6586828701610e42565b9250506040610f7686828701610e78565b9150509250925092565b600060ff82169050919050565b610f9681610f80565b82525050565b6000602082019050610fb16000830184610f8d565b92915050565b600060208284031215610fcd57610fcc610df4565b5b6000610fdb84828501610e42565b91505092915050565b600060208284031215610ffa57610ff9610df4565b5b600061100884828501610e78565b91505092915050565b6000806040838503121561102857611027610df4565b5b600061103685828601610e42565b925050602061104785828601610e42565b9150509250929050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b6000600282049050600182168061109857607f821691505b602082108114156110ac576110ab611051565b5b50919050565b7f45524332303a207472616e7366657220616d6f756e742065786365656473206160008201527f6c6c6f77616e6365000000000000000000000000000000000000000000000000602082015250565b600061110e602883610d44565b9150611119826110b2565b604082019050919050565b6000602082019050818103600083015261113d81611101565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061117e82610e57565b915061118983610e57565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156111be576111bd611144565b5b828201905092915050565b7f45524332303a2064656372656173656420616c6c6f77616e63652062656c6f7760008201527f207a65726f000000000000000000000000000000000000000000000000000000602082015250565b6000611225602583610d44565b9150611230826111c9565b604082019050919050565b6000602082019050818103600083015261125481611218565b9050919050565b7f45524332303a20617070726f76652066726f6d20746865207a65726f2061646460008201527f7265737300000000000000000000000000000000000000000000000000000000602082015250565b60006112b7602483610d44565b91506112c28261125b565b604082019050919050565b600060208201905081810360008301526112e6816112aa565b9050919050565b7f45524332303a20617070726f766520746f20746865207a65726f20616464726560008201527f7373000000000000000000000000000000000000000000000000000000000000602082015250565b6000611349602283610d44565b9150611354826112ed565b604082019050919050565b600060208201905081810360008301526113788161133c565b9050919050565b7f45524332303a207472616e736665722066726f6d20746865207a65726f20616460008201527f6472657373000000000000000000000000000000000000000000000000000000602082015250565b60006113db602583610d44565b91506113e68261137f565b604082019050919050565b6000602082019050818103600083015261140a816113ce565b9050919050565b7f45524332303a207472616e7366657220746f20746865207a65726f206164647260008201527f6573730000000000000000000000000000000000000000000000000000000000602082015250565b600061146d602383610d44565b915061147882611411565b604082019050919050565b6000602082019050818103600083015261149c81611460565b9050919050565b7f45524332303a207472616e7366657220616d6f756e742065786365656473206260008201527f616c616e63650000000000000000000000000000000000000000000000000000602082015250565b60006114ff602683610d44565b915061150a826114a3565b604082019050919050565b6000602082019050818103600083015261152e816114f2565b9050919050565b7f45524332303a206d696e7420746f20746865207a65726f206164647265737300600082015250565b600061156b601f83610d44565b915061157682611535565b602082019050919050565b6000602082019050818103600083015261159a8161155e565b905091905056fea2646970667358221220e9f727b75643ac30ffb07d0b2ebcfa54669c50f1695d740311b0b79a6947850c64736f6c634300080a0033")
}
