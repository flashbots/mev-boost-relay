package datastore

func MakeBlockBuilderStatus(isHighPrio, isBlacklisted bool) BlockBuilderStatus {
	if isBlacklisted {
		return RedisBlockBuilderStatusBlacklisted
	} else if isHighPrio {
		return RedisBlockBuilderStatusHighPrio
	} else {
		return RedisBlockBuilderStatusLowPrio
	}
}
