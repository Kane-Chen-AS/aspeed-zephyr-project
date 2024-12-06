# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
target_sources(app PRIVATE
	SPDMBuffer.c
	SPDMContext.c
	SPDMCrypto.c
	SPDMMain.c
	SPDMMctpBinding.c

	# Attester
	SPDMRequester.c
	RequestCmd/SPDMGetDigests.c
	RequestCmd/SPDMNegotiateAlgorithms.c
	RequestCmd/SPDMChallenge.c
	RequestCmd/SPDMGetCertificate.c
	RequestCmd/SPDMGetVersion.c
	RequestCmd/SPDMGetCapabilities.c
	RequestCmd/SPDMGetMeasurements.c

	# Attestee
	SPDMResponder.c
	ResponseCmd/SPDMDigests.c
	ResponseCmd/SPDMCapabilities.c
	ResponseCmd/SPDMAlgorithms.c
	ResponseCmd/SPDMMeasurements.c
	ResponseCmd/SPDMCertificate.c
	ResponseCmd/SPDMVersion.c
	ResponseCmd/SPDMChallengeAuth.c
	ResponseCmd/GetMeasurementImpl.c
	)

if(CONFIG_SECURE_CONNECTION_RESPONDER OR CONFIG_SECURE_CONNECTION_REQUESTER)
target_sources(app PRIVATE
	SPDMSession.c
	SPDMKeyOperation.c
)
endif()

if(CONFIG_SECURE_CONNECTION_REQUESTER)
target_sources(app PRIVATE
	RequestCmd/SPDMKeyExchange.c
	RequestCmd/SPDMFinish.c
	RequestCmd/SPDMGetEncap.c
	RequestCmd/SPDMHeartBeat.c
	RequestCmd/SPDMEnd.c
)
endif()

if(CONFIG_SECURE_CONNECTION_RESPONDER)
target_sources(app PRIVATE
	ResponseCmd/SPDMKeyExchangeRsp.c
	ResponseCmd/SPDMFinishRsp.c
	ResponseCmd/SPDMHeartBeatRsp.c
	ResponseCmd/SPDMEndSession.c
	ResponseCmd/SPDMPSKExchange.c
	ResponseCmd/SPDMEncapHandle.c
	ResponseCmd/SPDMKeyUpdate.c
)
endif()
# Request Commands
