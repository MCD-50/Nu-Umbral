# Nu-Nucypher
> This code contains python implementation of Nucypher's Umbral library.
> Code runs on mock net and and uses redis as a primary store for storing the capsule and policy.

> > For Platform visit https://github.com/mcd-50/Nu-Platform
> For NuCypher visit https://github.com/mcd-50/Nu-Umbral
> For Solidity visit https://github.com/mcd-50/Nu-Solidity
> For Frontend visit https://github.com/mcd-50/Nu-Frontend


## Demo Url
http://35.200.190.101:10002 (frontend platform url)

## Other Urls
* http://35.200.190.101:8545 (private blockchain url)
* http://35.200.190.101:10003 (private explorer url)
* http://35.200.190.101:10001 (backend api url)

###### Genobank DNA wallet

> To empower the world to upload FDA approved Saliva DNA extraction information on blockchain, stored on IPFS to enable an anonymous and encrypted way powered by NuChyper to interact with the World’s Genomic ecosystem with privacy & control.


## How Platform Works

- First Bob will create an account by providing the email (Used only for communication purpose for now) and password (a password for generating the blockchain address).

- Now bob will get the following values and needs only the accountAddress and password for using the platform services.
  * accountAddress (Ethereum address)
  * publicKey (Nucypher public key)
  * privateKey (Nucypher private key)
- Now Bob will upload the data by filling the folloing values (Since system is anonymous there is no login and all)
  * accountAddress
  * password
  * publicKey
  * privateKey
  * detail about the DNA
  * file (blob)
  
- Once bob uploads the data. It will be encrypyted and hosted to IPFS. For encryption Bob's (publicKey, privateKey) will be used and following will be generated
  * capsule (capsule object which be stored against a capsuleId[uuid])
  * ciphettext
  
- Now these two values (capsuleId, ciphertext) will stored on blockchain by calling our solidty contract and transaction hash will be generated.

- Bob will get the capsuleId (aka salivaId) and transactionHash of the blockchain transaction

- The capsuleId and deatils of DNA data (like whose DNA is this and all) will be visible to everyone.

- Suppose alice wants to access the DNA data after looking and DNA details

- Now alice will create an account by providing the email (Used only for communication purpose for now) and password (a password for generating the blockchain address).

- Alice will create a "Request access" by providing the following details
  * accountAddress (alice's)
  * Nucypher publicKey (alice's) for creating the policy where kfrags are attached
  * capsuleId
  * password (alice's)
  
- A mail will be sent to Bob's email address for the consent. Bob can give his consent by clicking the link in email.

- Once bob give the concent a policyId will be generated and for Alice and alice will get an email containing a secret code to access the policyId and transaction will be made on blockchain with following values
  * policyId
  * capsuleId
  * pubKey
  * singingPubKey

- Now alice will go to the "decode page" and paste the received secret code.

- Upon decode request the kfrags will be extracted and attached to the capsule (fetched from capsule map using capsuleId). And decrypted IPFS file link will be shared with the Alice.


###### This explains our platform (POC) working in a nutshell.

## Challenges we faced

* Setting up python backend and interacting with the umbral libraries
* Faced a lot of problems in set_correction_keys modules
* 16 Variable limit in solidity fuction
* and few we didn't counted on.
* IPFS uploaded file not showing on public gateway. 

## Futures improvements

* We wish to add admin policies
* QR codes
* Mobile app
* More robust communication channel.
* Handling encryption of the data

## Tech we used

* NodeJs
* React
* Geth
* Solidity
* Python (umbral)
* JavaScript

## Team members

* Daneil Uribe
* Sagar Jethi
* Ayush A.

## Video link

* Platform demo : https://youtu.be/sm4m0u8PJh0

## Screenshots

* ![Screenshot](UploadFile.png)
* ![Screenshot](UploadHistory.png)
* ![Screenshot](RequestAccess.png)
* ![Screenshot](Decode.png)
