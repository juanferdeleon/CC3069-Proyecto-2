/*
      Proyecto 2
  
  Programacion paralela
        con MPI

Creado por:

Juan Fernando De Leon Quezada   17822

*/


// ! Se tomara como base el programa bruteforce.cpp
// ! Se utilizara CryptoPP
// Crypto++ Library es una biblioteca gratuita de clase C ++ de esquemas criptográficos
// https://www.cryptopp.com/
// https://www.cryptopp.com/docs/ref/osrng_8h.html

#include "cryptopp/osrng.h"
#include <iostream>
#include <string>
#include <cstdlib>
#include <stdio.h>
#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/des.h"
#include "cryptopp/modes.h"
#include "cryptopp/secblock.h"
#include <fstream>

using namespace std;
using namespace CryptoPP;

int main(int argc, char* argv[]){
  // Main

  // Automatically Seeded Randomness Pool
  AutoSeededRandomPool prng;

  // class used to hold key
  SecByteBlock key(8);
  // Generate random array of bytes. 
	prng.GenerateBlock(key, 8);

  CryptoPP::byte initial_vector[DES::BLOCKSIZE] = {0};
	CryptoPP::byte private_key[DES::KEYLENGTH] = {250, 150, 0, 0, 0, 0, 0, 0};

  string plain_text, cipher_text, ciphered, recovered, line;

  ifstream input_file("plain_text.txt");

  if (input_file.is_open()){
    
    while (getline(input_file, line) ){
      plain_text = line;
    }
    
    input_file.close();
  
  } else {
    cout << "No fue posible abrir el archivo de entrada"; 
  }

  ciphered.clear();
	StringSource(private_key, 8, true, new HexEncoder(new StringSink(ciphered)));

  try {
		cout << "Texto plano: " << plain_text << endl;

		CBC_Mode< DES >::Encryption e;
		e.SetKeyWithIV(private_key, 8, initial_vector);

		// The StreamTransformationFilter adds padding as required. 
    // ECB and CBC Mode must be padded to the block size of the
    // cipher_text.
		StringSource(plain_text, true, new StreamTransformationFilter(e,new StringSink(cipher_text)));

	} catch(const CryptoPP::Exception& e) {
		cerr << e.what() << endl;
		exit(1);
	}

  ciphered.clear();
	StringSource(cipher_text, true, new HexEncoder(new StringSink(ciphered)));

  ofstream output_file("cipher_text.txt");
  if (output_file.is_open()){
      output_file << ciphered;
      output_file.close();
  } else {
    cout << "No fue posible abrir el archivo para escritura";
  }

	return 0;
  
}