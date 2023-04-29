#include <err.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <tee_client_api.h>

#include <TEEencrypt_ta.h>

int main(int argc, char *argv[]) {
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len = 64;
	FILE *fp;
	char keytext[sizeof(int)];
	char key_t[sizeof(int)];
	int encryptedkey;

	res = TEEC_InitializeContext(NULL, &ctx);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       NULL, NULL, NULL, &err_origin);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, 				TEEC_MEMREF_TEMP_OUTPUT,TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].tmpref.buffer = keytext;
	op.params[1].tmpref.size = sizeof(int);

	int opt;
	while ((opt = getopt(argc, argv, "ed")) != -1) {
		switch(opt) {
			case 'e':
				fp = fopen(argv[2], "r");
				if (fp == NULL) {
					printf("file not found : %s\n", argv[2]);
					return 1;
				}
				fgets(plaintext, 100, fp);
				fclose(fp);

				memcpy(op.params[0].tmpref.buffer, plaintext, len);

				res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);

				memcpy(ciphertext, op.params[0].tmpref.buffer, len);
				memcpy(key_t, op.params[1].tmpref.buffer, sizeof(int));

				encryptedkey = *((int*)key_t);

				fp = fopen("ciphertext.txt", "w");
				if (fp == NULL) {
					printf("File not found\n");
					return 1;
				}
				fputs(ciphertext, fp);
				fclose(fp);

				fp = fopen("encryptedkey.txt", "wt");
				if (fp == NULL) {
					printf("File not found\n");
					return 1;
				}
				fprintf(fp, "%d", encryptedkey);
				fclose(fp);

				break;
			case 'd':
				fp = fopen(argv[2], "r");
				if (fp == NULL) {
					printf("file not found : %s\n", argv[2]);
					return 1;
				}
				fgets(ciphertext, 100, fp);
				fclose(fp);

				memcpy(op.params[0].tmpref.buffer, ciphertext, len);

				fp = fopen(argv[3], "r");
				if (fp == NULL) {
					printf("file not found : %s\n", argv[2]);
					return 1;
				}
				fgets(ciphertext, 100, fp);
				fclose(fp);

				int ciphertext_key = atoi(ciphertext);

				memcpy(op.params[1].tmpref.buffer, &ciphertext_key, sizeof(int));

				res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

				memcpy(plaintext, op.params[0].tmpref.buffer, len);

				fp = fopen("result.txt", "w");
				if (fp == NULL) {
					printf("File not found\n");
					return 1;
				}
				fputs(plaintext, fp);
				fclose(fp);

				TEEC_CloseSession(&sess);
				TEEC_FinalizeContext(&ctx);
				break;
			default:
				printf("Invalid option\n");
				return 1;
		}
	}

	return 0;
}
