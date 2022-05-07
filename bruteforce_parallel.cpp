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
#include <mpi.h>
#include <fstream>

using namespace std;
using namespace CryptoPP;

#define KEYWORD "sencilla,"
#define KEY_SIZE 8

// Parámetros:
// 	- Objeto decifrador
// 	- Texto cifrado
// 	- Llave
// 	- Vector inicial
// Retorna:
// 	- Texto descifrado

string decode(
	CBC_Mode< DES >::Decryption decryptor,
	string cipher_text,
	CryptoPP::byte key[DES::KEYLENGTH],
	CryptoPP::byte initial_vector[DES::BLOCKSIZE]
){
	string recovered;
	decryptor.SetKeyWithIV(
		key,
		8,
		initial_vector
	);
	StringSource s(
		cipher_text,
		true, 
		new StreamTransformationFilter(decryptor,
			new StringSink(recovered), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING 
		) 
	); 
	return recovered;
}

// Parámetros:
// 	- Objeto decifrador
// 	- Texto cifrado
// 	- Llave
// 	- Vector inicial
// Retorna:
// 	- Booleano dependiendo si el texto descifrado contiene la palabra clave

bool probe_key(
	CBC_Mode< DES >::Decryption decryptor,
	string cipher_text,
	CryptoPP::byte key[DES::KEYLENGTH],
	CryptoPP::byte initial_vector[DES::BLOCKSIZE]
){
	return decode(decryptor, cipher_text, key, initial_vector).find(KEYWORD) != std::string::npos;	
}


// Main
// 	- Lee archivo de texto cifrado
// 	- Calcula rango de cada nodo
// 	- Cada noda evalua su rango de posibles llaves
// 	- Al encontrar la llave, envia mensaje a los demas nodos y finaliza el programa

int main(int argc, char* argv[])
{
	int key_is_found, my_rank, comm_size, flag = 0;
	MPI_Comm comm;
	MPI_Status status;
	MPI_Request request;
	double begin, end;

	AutoSeededRandomPool prng;
	SecByteBlock key(8);
	prng.GenerateBlock(key, 8);

	CryptoPP::byte initial_vector[DES::BLOCKSIZE] = {0};
	CryptoPP::byte private_key[DES::KEYLENGTH] = {0, 0, 0, 0, 0, 0, 0, 255};

	string plain_text, cipher_text, ciphered, recovered;

	MPI_Init(NULL, NULL);
	comm = MPI_COMM_WORLD;
	MPI_Comm_size(comm, &comm_size);
	MPI_Comm_rank(comm, &my_rank);

	if (my_rank == 0) {
		string line;
		ifstream input_file("encripted_text.txt");
		if (input_file.is_open())
		{
			while (getline(input_file, line) )
			{
				// cout << line << '\n';
				cipher_text = line;
			}
			input_file.close();
		}
		else cout << "No fue posible abrir el archivo de entrada"; 

		StringSource(
			cipher_text,
			true,
			new HexDecoder(
				new StringSink(ciphered)
			) // HexEncoder
		); // StringSource
		// cout << "Texto cifrado: " << cipher_text << endl;
   		
		MPI_Bcast(&ciphered, 1, MPI_CHAR, 0, comm);
    }

	begin = MPI_Wtime();
	try
	{
		unsigned long long int upper_limit = (unsigned long long int) pow(2, 64);
		unsigned long long int local_lower, local_upper, local_range;

		long int n_range = upper_limit / comm_size;
		local_lower = n_range * my_rank;
		local_upper = n_range * (my_rank + 1) - 1;

		// cout << "id : " << my_rank << " local lower: " << local_lower << " local upper: " << local_upper << "\n";

		if (my_rank == comm_size - 1) {
			local_upper = upper_limit;
		}

		MPI_Irecv(&key_is_found, 1, MPI_INT, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &request);
		CBC_Mode< DES >::Decryption d;

		unsigned char temporary_key[KEY_SIZE];
		unsigned char reversed_key[KEY_SIZE];
		memcpy(temporary_key, &local_lower, KEY_SIZE);
		unsigned long long int i = local_lower;

		while (i < local_upper && key_is_found == 0) {
			
			memcpy(temporary_key, &i, KEY_SIZE);
			reverse_copy(temporary_key, temporary_key + KEY_SIZE, reversed_key);

			// if (my_rank == 0) {
			// 	cout << "La llave es: " << (int) reversed_key[0] << (int) reversed_key[1] << (int) reversed_key[2] << (int) reversed_key[3] << (int) reversed_key[4] << (int) reversed_key[5] << (int) reversed_key[6] << (int) reversed_key[7] << "\n";
			// }

			if (probe_key(d, ciphered, temporary_key, initial_vector) || probe_key(d, ciphered, reversed_key, initial_vector)) {
				key_is_found = 1;
				end = MPI_Wtime();
				double elapsed = end - begin;

				cout << "La llave ha sido encontrada por: " << my_rank << "\n";
				// cout << "La llave es: " << (int) temporary_key[0] << (int) temporary_key[1] << (int) temporary_key[2] << (int) temporary_key[3] << (int) temporary_key[4] << (int) temporary_key[5] << (int) temporary_key[6] << (int) temporary_key[7] << "\n";
				cout << "Tiempo: " << elapsed << " segundos.\n";

				for (int branch = 0; branch < comm_size; branch++) {
					MPI_Send(&key_is_found, 1, MPI_INT, branch, my_rank, comm);
				}
				break;
			}

			MPI_Test(&request, &flag, &status);
			if (key_is_found) {
				break;
			}

			i++;
		}
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	MPI_Finalize();
		
	return 0;
}
