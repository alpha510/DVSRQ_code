#ifndef PAILLIER_H
#define  PAILLIER_H
#include <stdio.h>
#include "gmp.h"


extern gmp_randstate_t gmp_rand;

namespace phe {

	const int sigma = 128;

	class PaillierKey {

	public:
		mpz_t g, n, nsquare, half_n;

		PaillierKey();

		PaillierKey(mpz_t p, mpz_t q);

		PaillierKey(mpz_t n);

		PaillierKey(mpz_t g, mpz_t n, mpz_t nsqaure);

		PaillierKey(const PaillierKey &p);

		PaillierKey& operator=(const PaillierKey& p);
		
		~PaillierKey();
	};

	class PaillierPrivateKey : public PaillierKey {

	public:
		mpz_t lambda, lmdInv;

		PaillierPrivateKey();

		PaillierPrivateKey(mpz_t p, mpz_t q, mpz_t lambda);

		PaillierPrivateKey(mpz_t n, mpz_t lambda);

		PaillierPrivateKey(const PaillierPrivateKey &p);

		PaillierPrivateKey& operator=(const PaillierPrivateKey& p);

		/*
		Free the space occupied by lambda, lmdInv
		*/
		~PaillierPrivateKey();
	};

	class PaillierThdPrivateKey {

	public:
		mpz_t sk, n, nsqaure;

		PaillierThdPrivateKey();

		PaillierThdPrivateKey(mpz_t sk, mpz_t n, mpz_t nsqaure);

		PaillierThdPrivateKey(const PaillierThdPrivateKey &p);

		PaillierThdPrivateKey& operator=(const PaillierThdPrivateKey& p);

		~PaillierThdPrivateKey();

	};

	class Paillier {

	public:
		PaillierKey pubkey;
		PaillierPrivateKey prikey;

		Paillier();

		Paillier(PaillierKey pubkey);

		Paillier(PaillierPrivateKey prikey);

		Paillier(const PaillierKey &pubkey, const PaillierPrivateKey & prikey);

		Paillier(const Paillier &p);

		Paillier& operator=(const Paillier& p);
		

		~Paillier();

		void keygen(mpz_t p, mpz_t q);
		void keygen(unsigned long bitLen);
		void encrypt(mpz_t c, mpz_t m);
		void encrypt(mpz_t c, mpz_t m, mpz_t r);
		void decrypt(mpz_t m, mpz_t c);
		void add(mpz_t res, mpz_t c1, mpz_t c2);
		void sub(mpz_t res, mpz_t c1, mpz_t c2);
		void scl_mul(mpz_t resc, mpz_t c, mpz_t e);
		void scl_mul(mpz_t res, mpz_t c, int e);

		};

	class PaillierThd {

	public:
		PaillierThdPrivateKey psk;
		Paillier pai;
		mpz_t eone, ezero;

		PaillierThd();
		
		PaillierThd(PaillierThdPrivateKey psk);
		PaillierThd(PaillierThdPrivateKey psk, PaillierKey pubkey);

		PaillierThd(const PaillierThd& p);

		PaillierThd & operator=(const PaillierThd& p);

		~PaillierThd();
		void pdec(mpz_t pc, mpz_t c);
		void fdec(mpz_t m, mpz_t c1, mpz_t c2);
	};

	void setrandom();


	class ThirdKeyGen {
	public:
		void thdkeygen(Paillier &pai, int sigma,
			PaillierThd* cp, PaillierThd* csp);
	};
}

#endif
