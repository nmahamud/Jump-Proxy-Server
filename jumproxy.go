// socket-server project main.go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	// "crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"

	// "encoding/hex"
	// "bufio"
	"log"

	// "github.com/go-delve/delve/pkg/dwarf/reader"
	"golang.org/x/crypto/pbkdf2"
)

const (
	SERVER_HOST   = "localhost"
	SERVER_PORT   = "9988"
	SERVER_TYPE   = "tcp"
	SALT          = "Honkai Star Rail"
	OUTGOING_PORT = "9989"
	TEST_PHRASE   = "Kafka"
)

var (
	KEY_LOCATION = ""
	KEY_PHRASE   = ""
	REVERSE_PORT = ""
	HOST_NAME    = ""
	HOST_PORT    = ""
)

func main() {
	// Parse the arguments
	args := os.Args
	for index, element := range args {
		if index > 0 {
			if element == "-k" {
				KEY_LOCATION = args[index+1] // set the keylocation
			} else if element == "-l" {
				REVERSE_PORT = args[index+1] // set the neww port to listen to
			} else if args[index-1] != "-k" && args[index-1] != "-l" {
				if HOST_NAME == "" {
					HOST_NAME = args[index]
				} else {
					HOST_PORT = args[index]
				}
			}
		}
	}

	// Get the keyphrase
	phrase, err := os.ReadFile(KEY_LOCATION)
	if err != nil {
		panic(err)
	}
	KEY_PHRASE = string(phrase)

	if REVERSE_PORT != "" {
		serverMain()
	} else {
		clientMain()
	}
}

func clientMain() {
	server, err := net.Dial(SERVER_TYPE, HOST_NAME+":"+HOST_PORT) // connect to the new server
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	defer server.Close()
	clientSendRec(server)

}

func clientSendRec(server net.Conn) {
	go func() {
		for {
			buffer := make([]byte, 8196)
			mLen, err := os.Stdin.Read(buffer)
			if err != nil {
				fmt.Println("Error reading:", err.Error())
			}
			encryptedText := encryptIt(buffer[:mLen], KEY_PHRASE)
			io.WriteString(server, string(encryptedText))
			fmt.Println("At line 94: ", len(encryptedText), "clint got from stdin: ", mLen)
		}
	}()

	// go func() {
	for {
		rBuffer := make([]byte, 8224)
		mLen, err := server.Read(rBuffer)
		if err != nil {
			fmt.Println("Error reading:", err.Error())
		}
		decryptedText := decryptIt(rBuffer[:mLen], KEY_PHRASE)
		io.WriteString(os.Stdin, string(decryptedText))
		fmt.Println("At line 107: ", len(decryptedText), "clint got from server: ", mLen)
	}
	// }()
}

func serverMain() {
	fmt.Println("Server Running...")
	server, err := net.Listen(SERVER_TYPE, SERVER_HOST+":"+REVERSE_PORT) // check for traffic in the port
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	defer server.Close()
	fmt.Println("Listening on " + SERVER_HOST + ":" + REVERSE_PORT)
	fmt.Println("Waiting for client...")
	for {
		connection, err := server.Accept()

		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		fmt.Println("client connected")
		go processClient(connection)
	}
}
func processClient(connection net.Conn) {
	jumpServer, jErr := net.Dial(SERVER_TYPE, HOST_NAME+":"+HOST_PORT) // connect to the port you want to send traffic to

	if jErr != nil {
		panic(jErr)
	}
	go func() {
		for {
			buffer := make([]byte, 8224)
			mLen, err := connection.Read(buffer)
			if err != nil {
				if err == io.EOF {
					break
				}
				fmt.Println("Error reading at line 144:", err.Error())
			}
			decryptedText := decryptIt(buffer[:mLen], KEY_PHRASE)
			io.WriteString(jumpServer, string(decryptedText))
			fmt.Println("At line 151: ", len(decryptedText), "server got from client: ", mLen)
		}
	}()

	// go func() {
	for {
		buffer := make([]byte, 8196)
		mLen, err := jumpServer.Read(buffer)
		if err != nil {
			// if err == io.EOF {
			// 	continue
			// }
			fmt.Println("Error reading at line 163:", err.Error())
		}
		// if err != io.EOF {
		fmt.Println(string(buffer[:mLen]))
		encryptedText := encryptIt(buffer[:mLen], KEY_PHRASE)
		io.WriteString(connection, string(encryptedText))
		fmt.Println("At line 167: ", len(encryptedText), "server got from jump: ", mLen)
	}
	// }()

}

func pbkdf2Key(input string) []byte {
	byteInput := []byte(input)
	key := pbkdf2.Key(byteInput, []byte(SALT), 4096, 32, sha1.New)
	return key // by referring to it as a string
}

func encryptIt(value []byte, keyPhrase string) []byte {
	aesBlock, err := aes.NewCipher([]byte(pbkdf2Key(keyPhrase)))
	if err != nil {
		fmt.Println(err)
	}

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		fmt.Println(err)
	}
	nonce := make([]byte, gcmInstance.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)

	cipheredText := gcmInstance.Seal(nonce, nonce, value, nil)

	return cipheredText
}

func decryptIt(ciphered []byte, keyPhrase string) []byte {
	aesBlock, err := aes.NewCipher([]byte(pbkdf2Key(keyPhrase)))
	if err != nil {
		log.Fatalln(err)
	}

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		log.Fatalln(err)
	}
	nonceSize := gcmInstance.NonceSize()
	nonce, cipheredText := ciphered[:nonceSize], ciphered[nonceSize:]

	originalText, err := gcmInstance.Open(nil, nonce, cipheredText, nil)
	if err != nil {
		log.Fatalln(err)
	}
	return originalText

}
