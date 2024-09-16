










    def send_poke(self, recipient):
        if not self.is_registered_user(recipient):
            print(f"Recipient {recipient} is not registered.")
            return
        
        print(f"Poking {recipient} to request key exchange.")
        
        # Generate symmetric key immediately upon sending poke
        recipient_public_key = self.get_public_key(recipient)
        if not recipient_public_key:
            print(f"Could not retrieve public key for {recipient}.")
            return

        symmetric_key = os.urandom(32)
        encrypted_symmetric_key = encrypt_key_with_rsa(recipient_public_key, symmetric_key)

        poke_message = {
            'type': 'poke',
            'sender': self.get_fullname(),
            'recipient': recipient,
            'symmetric_key': encrypted_symmetric_key,
            'message': 'Key exchange request',
            'timestamp': time.time()
        }

        # Encrypt the poke message with the symmetric key
        encrypted_message = encrypt_message(json.dumps(poke_message), self.symmetric_key)
        self.add_to_blockchain(encrypted_message)

        # Store symmetric key for this recipient
        self.recipient_symmetric_keys[recipient] = symmetric_key

        print(f"Poke and key exchange sent to {recipient}")



    def handle_poke(self, message):
        print(f"Received poke from {message['sender']}.")
        
        # Confirm key exchange request
        user_input = input(f"Do you accept the key exchange request from {message['sender']}? (y/n)")
        
        if user_input.lower() == 'y':
            print(f"Accepting key exchange from {message['sender']}.")
            self.store_symmetric_key(message['sender'], message['symmetric_key'])
        else:
            print("Key exchange rejected.")



    def send_poke_response(self, recipient, response_type):
        response_message = {
            'type': 'poke_response',
            'sender': self.get_fullname(),
            'recipient': recipient,
            'response': response_type,  # 'accept' or 'reject'
            'timestamp': time.time()
        }

        # Encrypt the response
        encrypted_message = encrypt_message(json.dumps(response_message), self.symmetric_key)
        print(f"\033[93mEncrypted poke response ({response_type}): {encrypted_message}\033[0m")  # Debugging log for response
        self.add_to_blockchain(encrypted_message)

        print(f"\033[92mPoke response ({response_type}) sent to {recipient} and added to the blockchain.\033[0m")


    def handle_poke_response(self, message):
        print(f"\033[92mReceived poke response from {message['sender']}: {message['response']}.\033[0m")
        print(f"\033[93mPoke response message details: {message}\033[0m")  # Debugging log for response message

        if message['response'] == 'accept':
            # Proceed with the key exchange and message communication
            print(f"\033[92mKey exchange accepted. Proceeding to open communication with {message['sender']}.\033[0m")
            self.exchange_keys(message['sender'])
        else:
            print(f"\033[91mKey exchange rejected by {message['sender']}.\033[0m")


    def exchange_keys(self, recipient):
        recipient_public_key = self.get_public_key(recipient)
        if not recipient_public_key:
            print(f"\033[91mCould not retrieve public key for {recipient}.\033[0m")
            return

        print(f"\033[92mExchanging keys with {recipient}. Public key: {recipient_public_key}\033[0m")

        # Generate a symmetric key for the private message
        symmetric_key = os.urandom(32)
        encrypted_symmetric_key = encrypt_key_with_rsa(recipient_public_key, symmetric_key)
        print(f"\033[93mGenerated symmetric key: {symmetric_key}\033[0m")
        print(f"\033[93mEncrypted symmetric key: {encrypted_symmetric_key}\033[0m")  # Debug for symmetric key exchange

        key_exchange_message = {
            'type': 'key_exchange',
            'sender': self.get_fullname(),
            'recipient': recipient,
            'symmetric_key': encrypted_symmetric_key,
            'timestamp': time.time()
        }

        encrypted_message = encrypt_message(json.dumps(key_exchange_message), self.symmetric_key)
        print(f"\033[93mEncrypted key exchange message: {encrypted_message}\033[0m")  # Debug for key exchange
        self.add_to_blockchain(encrypted_message)

        # Store symmetric key for future private messages
        self.recipient_symmetric_keys[recipient] = symmetric_key
        print(f"\033[92mKeys exchanged and ready for communication with {recipient}.\033[0m")


    def handle_key_exchange(self, message):
        print(f"\033[92mReceived key exchange from {message['sender']}.\033[0m")
        print(f"\033[93mKey exchange message details: {message}\033[0m")  # Debugging log for key exchange message
        encrypted_symmetric_key = message['symmetric_key']
        
        # Decrypt the symmetric key with your private key
        symmetric_key = decrypt_key_with_rsa(self.private_key, encrypted_symmetric_key)
        print(f"\033[93mDecrypted symmetric key: {symmetric_key}\033[0m")  # Debug for decrypted symmetric key

        # Store the symmetric key for future communication
        self.recipient_symmetric_keys[message['sender']] = symmetric_key

        print(f"\033[92mKey exchange complete. Ready to communicate securely with {message['sender']}.\033[0m")