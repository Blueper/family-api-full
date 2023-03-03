const express = require('express');
const router = express.Router();
const pkceChallenge = require('pkce-challenge').default;
const { FusionAuthClient } = require('@fusionauth/typescript-client');
const clientId = '7d31ada6-27b4-461e-bf8a-f642aacf5775';
const clientSecret = 'yz-hU1HZRZzAml2YJdM7-Dtafksq2-lm6sEFxAPS_6g';
const client = new FusionAuthClient('Y808ZszXwPcsXvrFsBzMdmJ7N4Lv85yLkZtJcEnJc1f3GwRO56b2RLns', 'https://fusionauth.ritza.co');
const consentId = 'e5e81271-847b-467e-b172-770fa806f894';


// Route handler
router.get('/', async function (req, res, next) {
    try {
        let familyProfiles = [];
        const pkce_pair = pkceChallenge();
        req.session.verifier = pkce_pair['code_verifier'];
        req.session.challenge = pkce_pair['code_challenge'];
        if (req.session.user && req.session.user.id) {
            const response = await client.retrieveFamilies(req.session.user.id);
            if (response.response.families && response.response.families.length >= 1) {
                let familyMembers = response.response.families[0].members.filter(elem => elem.role !== 'Adult' || elem.userId === req.session.user.id);
                const userProfiles = await getUserProfiles(familyMembers);
                userProfiles.forEach(user => {
                    let self = familyMembers.filter(elem => elem.userId == user.response.user.id)[0];
                    user.response.user.role = self.role;
                });
                familyProfiles = buildFamilyArray(userProfiles);
                const consentsResponseArray = await getUserConsentStatuses(familyMembers);
                familyProfiles = updateFamilyWithConsentStatus(familyProfiles, consentsResponseArray);
            }
        }
        res.render('index', {
            family: familyProfiles,
            user: req.session.user,
            title: 'Family Example',
            challenge: pkce_pair['code_challenge']
        });
    } catch (error) {
        console.error("in error");
        console.error(JSON.stringify(error));
        next(error);
    }
});

// Named functions
async function getUserProfiles(familyUsers) {
    const getUsers = familyUsers.map(elem => client.retrieveUser(elem.userId));
    const profiles = await Promise.all(getUsers);
    return profiles;
}

async function getUserConsentStatuses(users) {
    const getUserConsentStatuses = users.map(elem => client.retrieveUserConsents(elem.userId));
    const consentsResponseArray = await Promise.all(getUserConsentStatuses);
    return consentsResponseArray;
}

function buildFamilyArray(users) {
    const family = [];
    users.forEach(user => {
        family.push({ "id": user.response.user.id, "email": user.response.user.email, "role": user.response.user.role });
    });
    return family;
}
function updateFamilyWithConsentStatus(family, consentsResponseArray) {
    const userIdToStatus = {};
    const userIdToUserConsentId = {};
    consentsResponseArray.forEach((consent) => {
        const matchingConsent = consent.response.userConsents.filter((userConsent) => userConsent.consent.id == consentId)[0];
        if (matchingConsent) {
            const userId = matchingConsent.userId;
            userIdToUserConsentId[userId] = matchingConsent.id;
            userIdToStatus[userId] = matchingConsent.status;
        }
    });
    return family.map((member) => {
        member["status"] = userIdToStatus[member.id];
        member["userConsentId"] = userIdToUserConsentId[member.id];
        return member;
    });
}

/* OAuth return from FusionAuth */
router.get('/oauth-redirect', async function (req, res, next) {
    try {
        const response = await client.exchangeOAuthCodeForAccessTokenUsingPKCE(
            req.query.code,
            clientId,
            clientSecret,
            'http://localhost:3000/oauth-redirect',
            req.session.verifier
        );

        req.session.state = req.query.state;

        const userResponse = await client.retrieveUserUsingJWT(
            response.response.access_token
        );

        req.session.user = userResponse.response.user;

        res.redirect(302, '/');
    } catch (err) {
        console.log('in error');
        console.error(JSON.stringify(err));
    }
});

/* Change consent */
router.post('/change-consent-status', async function (req, res, next) {
    if (!req.session.user) {
        // force signin
        res.redirect(302, '/');
    }
    const userConsentId = req.body.userConsentId;
    let desiredStatus = req.body.desiredStatus;
    if (desiredStatus != 'Active') {
        desiredStatus = 'Revoked';
    }

    // check current user is an adult
    const response = await client.retrieveFamilies(req.session.user.id);
    if (response.response.families && response.response.families.length >= 1) {
        let self = response.response.families[0].members.filter(elem => elem.userId == req.session.user.id)[0];
        if (self.role !== 'Adult') {
            res.send(403, 'Only Adult users can change consents');
        }
    }

    if (!userConsentId) {
        return res.send(400, 'No userConsentId provided!');
    }

    const patchBody = { userConsent: { status: desiredStatus } };
    try {
        const response = await client.patchUserConsent(userConsentId, patchBody);
        res.redirect(302, '/');
    } catch (err) {
        console.log('in error');
        console.error(JSON.stringify(err));
        next(err);
    }
});

module.exports = router;
