#ifndef __KT2_H__
#define __KT2_H__

// ����� ������� �������������� ��������
#define SUPPORTED_CLA									0x80

// ��� ���������� ���������� ������������ �����������������
#define LIBRARY_INS										0xaa
// ������� ������ �����
#define OPEN_SESSION_P1									0x10
// ������� ��������� �����
#define CLOSE_SESSION_P1								0x20

// ��� ���������� ���������� �������������� �������
#define PERSO_INS										0xec
// ������� ����������������� ������
#define PERSONALIZE_P1									0x10

// ��� ���������� ���������� ����������������� PIN/PUK-������
#define USER_INS										0x0a
// ��� ���������� ���������� ������ �������������� ������������
#define SECURITY_OFFICER_INS							0x3a
// ������� ��������� ��� ������������ ��� ���� �������������� ������������
#define VERIFY_P1										0x10
// ������� ������� ��� ������������ ��� ���� �������������� ������������
#define MODIFY_P1										0x20
// ������� ���������� PIN/PUK-����
#define SET_P1											0x30

// ��� ���������� ���������� ���������
#define OBJECT_MGMT_INS									0x1c
// ������� �������� ������ ��������
#define GET_OBJECT_LIST_P1								0x10
// ������� ������������� ���������� �������� ����
#define IMPORT_TRUSTED_PUBLIC_KEY_P1					0x20
// ������� ������� ���������� ��������� ����
#define CREATE_TRUSTED_SECRET_KEY_P1					0x40
// ������� ������������� �������� ����
#define GENERATE_KEY_PAIR_P1							0x50
// ������� ������� ������
#define DELETE_OBJECT_P1								0x60
// ������� �������� �������� ����
#define GET_PUBLIC_KEY_P1								0x70

// ��� ���������� ���������� ��������� ������
#define SERVICE_INS										0x38
// ������� �������� �������� �����
#define LOGOUT_P1										0x10
// ������� �������� ������
#define GET_APPLET_DATA_P1								0x20
// ������� ���������� ������
#define SET_APPLET_DATA_P1								0x30
// ������� ��������� ����������� �����
#define CALCULATE_APPLET_CHECKSUM_P1					0x40

// ��� ���������� �����������������
#define ADMINISTRATION_INS								0x3c
// ������� �������� �������� ��������� ������� �������� PIN/PUK-�����
#define RESET_FAILED_ATTEMPTS_COUNTER_P1				0x10
// ������� �������� ��������� ��������
#define CHANGE_PIN_POLICY_P1							0x20
// ������� ���������������� ������
#define APPLET_INITIALIZATION_P1						0x30
// ������� ������������� �������� ���� �������
#define GENERATE_APPLET_KEY_PAIR_P1						0x40

// ��� ���������� ���������� ����������������� ������
#define CRYPTO_INS										0x3e
// ������� ���������
#define SIGN_P1											0x10
// ������� ��������� �������
#define VERIFY_SIGNATURE_P1								0x20
// ������� ������ �����������
#define HASH_INIT_P1									0x30
// ������� ���������� �����������
#define HASH_UPDATE_P1									0x40
// ������� ��������� �����������
#define HASH_FINAL_P1									0x50
// ������� ������ ���������� HMAC
#define HMAC_INIT_P1									0x60
// ������� ���������� ���������� HMAC
#define HMAC_UPDATE_P1									0x70
// ������� ��������� ���������� HMAC
#define HMAC_FINAL_P1									0x80
// ������� ����������� ���������� ����
#define PREPARE_KEY_P1									0x90
// ������� ������ �������������� �� ���� 28147-89
#define CRYPTO_INIT_P1									0xa0
// ������� ���������� ����������
#define CRYPTO_UPDATE_P1								0xb0
// ������� ��������� ����������
#define CRYPTO_FINAL_P1									0xc0
// ������� ������������� ������������������ ��������� �����
#define GENERATE_RANDOM_P1								0xd0

// ��� ���������� ���������� �������� ��������
#define FILE_SYSTEM_INS									0x4c
// ������� ������� ����� ��� ������ ������
#define CREATE_DATA_BUFFER_P1							0x10
// ������� �������� ������
#define WRITE_DATA_P1									0x20
// ������� ��������� ����� ��� ����
#define SAVE_DATA_BUFFER_AS_FILE_P1						0x30
// ������� ������� �����
#define CREATE_FOLDER_P1								0x40
// ������� ������� ����
#define DELETE_FILE_P1									0x50
// ������� ��������� ����
#define READ_FILE_P1									0x60
// ������� �������� ������ ������
#define GET_FILE_LIST_P1								0x70
// ������� ������� ����
#define SELECT_FILE_P1									0x80
// ������� �������� ��������� ���� �������
#define CHANGE_AC_P1									0x90
// ������� ��������� ������� �����������
#define VERIFY_CERTIFICATE_P1							0xa0

// ��� ���������� ���������� ���������� �������
#define SECURE_CHANNEL_INS								0x4e
// ������� ������ ��������� ����������� ������
#define INITIALIZE_UPDATE_P1							0x10
// ������� ��������� ��������� ����������� ������
#define EXTERNAL_AUTHENTICATE_P1						0x20
// ������� �������� ������ ����������� ������
#define CHANGE_SECURE_CHANNEL_STATUS_P1					0x30

// ��� ���������� ����������� � ������ ����
#define EMBEDDED_INS									0x5c
// ������� ������������� ���� ������ �����
#define GEN_SESSION_KEY_P1								0x10
// ������� ��������� ������� ������� ������
#define VERIFY_WITH_EXTERNAL_KEY_P1						0x20

// ��� ���� / ����� ������
typedef enum PIN_TYPE
{
	GUEST,										// �������� ����� ������
	SO,											// ���� �������������� ������������
	USER,										// PIN-��� ������������
	SIGN,										// PIN-��� �������
	PUK,										// PUK-���
    RESET,                                      // PIN-��� ������ � ��������� ����������
	TRANSPORT									// ������������ ����
}
PinType, WorkMode;

// ��� �������
typedef enum OBJECT_TYPE
{
	PUBLIC_KEY = 1,								// �������� �����
	SECRET_KEY,									// ��������� �����
	KEY_PAIR									// �������� ����
}
ObjectType;

// ��� �����
typedef enum FILE_TYPE
{
	FILE_TYPE_EF = 1,							// ���� ������
	FILE_TYPE_DF,								// �����
	FILE_TYPE_MF								// �������� ����������
}
FileType;

enum ISO7816_OFFSET
{
	CLA, INS, P1, P2, LC, CDATA
};

typedef enum SW
{
	SW_WRONG_LENGTH = 0x6700,					// �������� ����� �������

	SW_PIN_NOT_INITIALIZED = 0x6701,			// 6701h ���-��� �� ���������������
	SW_PIN_LENGTH_INVALID,						// 6702h ������������ ����� ���-����
	SW_PIN_BLOCKED,								// 6703h ���-��� ������������
	SW_PIN_INVALID,								// 6704h �������� ���-���
	SW_PIN_NOT_VERIFIED,						// 6705h ����� � ������� ���-����� �� ��� ������
	SW_PIN_ALREADY_INITIALIZED,					// 6706h ���-��� ��� ���������������
	SW_RNG_FAILED,								// 6707h ������ ����
	SW_OBJECT_NOT_FOUND,						// 6708h ��������� ������ �� ������
	SW_OBJECT_STORAGE_FULL,						// 6709h ��������� ������������ ���������� �������� ���������� ����
	SW_SIGNATURE_INVALID,						// 670Ah ������������ �������
	SW_INVALID_DATA,							// 670Bh ������� �������� ������ � APDU �������
	SW_PIN_TYPE_INVALID,						// 670Ch �������� ��� ���-����
	SW_OBJECT_TYPE_INVALID,						// 670Dh �������� ��� �������
	SW_SIGN_PIN_NOT_PRESENT,					// 670Eh PIN-��� ������� �� ����������
	SW_OPERATION_NOT_PERMITTED,					// 670Fh �������� �� ����� ���� ���������
	SW_OPERATION_NOT_INITIALIZED,				// 6710h �������� �� ���� ����������������
	SW_FILE_SYSTEM_FULL,						// 6711h ��������� ������������ ���������� ������
	SW_CAN_NOT_DELETE_MF,						// 6712h ������ ������� �������� ���������� �������� �������
	SW_DF_NOT_EMPTY,							// 6713h ������ ������� �� ������ ����������
	SW_FILE_NOT_FOUND,							// 6714h ��������� ���� �� ������
	SW_INVALID_PARAMETERS,						// 6715h ������ �������� �������� � ADPU �������
	SW_INVALID_OFFSET_OR_LENGTH,				// 6716h ����� �� ������� �������� ����� ��� ��� ������/������
	SW_INVALID_FILE_TYPE,						// 6717h ������ �������� ��� �����
	SW_FILE_ALREADY_EXISTS,						// 6718h ���� � ��������� ������ ��� ������
	SW_AC_NOT_SATISFIED,						// 6719h ��� ���� ��� ���������� �������� � ��������� ������
	SW_INVALID_LIFE_CYCLE_STATE,				// 671Ah �������� ��������� ��������������/������������� �������
	SW_DECRYPTING_KEY,							// 671Bh ������ ������������� �����
	SW_TOKEN_MEMORY_FULL,						// 671Ch �� ������ ��� ��������� ������
	SW_INVALID_CERT_CONTENT,					// 671Dh ������������ ���������� ����������� ���������� �����
	SW_PIN_NOT_FULFIL_PASSWORD_POLICY,			// 671Eh ������� �������� ���-���� �� ������������� ����������� ��������� ��������
	SW_PIN_CHANGE_REQUIRED,						// 671Fh ���������� ��������� �������� �������� ���-����
	SW_INTEGRITY_CONTROL_NOT_PASSED,			// 6720h ������ ������������� �������� ����������� �������
	SW_INVALID_SECURE_CHANNEL_COMMAND,			// 6721h �������� �������� ������������� APDU �������
	SW_CMD_CAN_NOT_BE_TRANSMITTED_UNENCRYPTED,	// 6722h APDU ������� �� ����� ���� �������� � �������� ����
	SW_NONCONFORMANCE_KEY_ALG_OR_PARAMS,		// 6723h ������������ �������� ��������� �/��� ��������� �����
	SW_CMD_CAN_NOT_BE_PASSED_OVER_SC,			// 6724h APDU ������� �� ����� ���� �������� �� ����������� ������
	SW_PUBLIC_KEY_INVALID,						// 6725h �������� �������� ��������� �����
	SW_ZERO_UKM,								// 6726h ������� �������� UKM
	SW_CPRO_INVALID_COUNTER_VALUE,				// 6727h ������������ �������� ���� �� ������ �� ��������� ����������� ������ ���������
	SW_INVALID_PUBLIC_KEY_USAGE,				// 6728h ������������ ������������� ����������� ��������� �����

	SW_UNKNOWN = 0x6f00,						// ����������� ������
	SW_CLA_NOT_SUPPORTED = 0x6e00,				// ���������������� ����� �������
	SW_INS_NOT_SUPPORTED = 0x6d00,				// ���������������� ���������� �������
	SW_APPLET_NOT_FOUND = 0x6A82,				// ���� �� ������ (������ �����������)
	SW_INCORRECT_P1P2 = 0x6a86,					// �������� ��������� �������

	SW_NO_ERROR = 0x9000						// �������� ���������� �������
}
SW;

#define IS_SW(x) ((x) >= SW_WRONG_LENGTH && (x) <= SW_NO_ERROR)

#endif /* #ifndef __KT2_H__ */
