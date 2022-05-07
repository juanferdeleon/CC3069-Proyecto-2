/*
      Proyecto 2
  
  Programacion paralela
        con MPI

Creado por:

Juan Fernando De Leon Quezada   17822

*/

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
#include <sys/time.h>
#include <fstream>

using namespace std;
using namespace CryptoPP;

#define KEYWORD "sencilla,"

string decode(CBC_Mode< DES >::Decryption decryptor,string cipher_text,CryptoPP::byte key[DES::KEYLENGTH],CryptoPP::byte initial_vector[DES::BLOCKSIZE]){
	
    string recovered;
	decryptor.SetKeyWithIV(key,8,initial_vector);
	StringSource s(cipher_text, true, new StreamTransformationFilter(decryptor,new StringSink(recovered), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING ));
	
    return recovered;

}

bool probe_key(CBC_Mode< DES >::Decryption decryptor,string cipher_text,CryptoPP::byte key[DES::KEYLENGTH],CryptoPP::byte initial_vector[DES::BLOCKSIZE]){
	
    return decode(decryptor, cipher_text, key, initial_vector).find(KEYWORD) != std::string::npos;	

}



int main(int argc, char* argv[]){
    
    AutoSeededRandomPool prng;

	SecByteBlock key(8);
	prng.GenerateBlock(key, 8);

	CryptoPP::byte initial_vector[DES::BLOCKSIZE] = {0};
	CryptoPP::byte private_key[DES::KEYLENGTH] = {0, 0, 0, 0, 0, 0, 0, 255};
	CryptoPP::byte reversed_key[DES::KEYLENGTH] = {0, 0, 0, 0, 0, 0, 0, 255};

	string plain_text, cipher_text, ciphered, recovered, line;

    ifstream input_file("encripted_text.txt");
    
    if (input_file.is_open()){

        while (getline(input_file, line) ){
            cipher_text = line;
        }
        
        input_file.close();
    } else {
        cout << "No fue posible abrir el archivo de entrada"; 
    }

	StringSource(cipher_text, true, new HexDecoder(new StringSink(ciphered)));

    // Measure time
    struct timeval begin, end;
    gettimeofday(&begin, 0);

    try{
		private_key[0] = (CryptoPP::byte)0;
		private_key[1] = (CryptoPP::byte)0;
		private_key[2] = (CryptoPP::byte)0;
		private_key[3] = (CryptoPP::byte)0;
		private_key[4] = (CryptoPP::byte)0;
		private_key[5] = (CryptoPP::byte)0;
		private_key[6] = (CryptoPP::byte)0;
		private_key[7] = (CryptoPP::byte)0;

		reversed_key[0] = (CryptoPP::byte)0;
		reversed_key[1] = (CryptoPP::byte)0;
		reversed_key[2] = (CryptoPP::byte)0;
		reversed_key[3] = (CryptoPP::byte)0;
		reversed_key[4] = (CryptoPP::byte)0;
		reversed_key[5] = (CryptoPP::byte)0;
		reversed_key[6] = (CryptoPP::byte)0;
		reversed_key[7] = (CryptoPP::byte)0;

		CBC_Mode< DES >::Decryption d;

		for(int i0 = 0; i0 < 255; i0++){
			private_key[0] = (CryptoPP::byte)i0;	
			for(int i1 = 0; i1 < 255; i1++){
				private_key[1] = (CryptoPP::byte)i1;
				for(int i2 = 0; i2 < 255; i2++){
					private_key[2] = (CryptoPP::byte)i2;
					for(int i3 = 0; i3 < 255; i3++){
						private_key[3] = (CryptoPP::byte)i3;
						for(int i4 = 0; i4 < 255; i4++){
							private_key[4] = (CryptoPP::byte)i4;
							for(int i5 = 0; i5 < 255; i5++){
								private_key[5] = (CryptoPP::byte)i5;
								for(int i6 = 0; i6 < 255; i6++){
									private_key[6] = (CryptoPP::byte)i6;
									for(int i7 = 0; i7 < 255; i7++){
										private_key[7] = (CryptoPP::byte)i7;

										reverse_copy(private_key, private_key + 8, reversed_key);

										if (probe_key(d, ciphered, private_key, initial_vector) || probe_key(d, ciphered, reversed_key, initial_vector)){
											cout << "La llave es: " << (int) private_key[0] << (int) private_key[1] << (int) private_key[2] << (int) private_key[3] << (int) private_key[4] << (int) private_key[5] << (int) private_key[6] << (int) private_key[7] << "\n";
											cout << "La llave ha sido encontrada \n";
											// Detener el tiempo, calcular el tiempo de ejecucion
											gettimeofday(&end, 0);
											long seconds = end.tv_sec - begin.tv_sec;
											long microseconds = end.tv_usec - begin.tv_usec;
											double elapsed = seconds + microseconds * 1e-6;
											cout << "Tiempo: " << elapsed << " segundos.\n";

											return 0;
										}
									}
								}
							}
						}
					}
				}
			}
		}
	} catch(const CryptoPP::Exception& e) {
		cerr << e.what() << endl;
		exit(1);
	}
    return 0;
}