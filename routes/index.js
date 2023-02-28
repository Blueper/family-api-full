const express = require('express');
const router = express.Router();
const pkceChallenge = require('pkce-challenge').default;
const {FusionAuthClient} = require('@fusionauth/typescript-client');
const clientId = '7d31ada6-27b4-461e-bf8a-f642aacf5775';
const clientSecret = 'yz-hU1HZRZzAml2YJdM7-Dtafksq2-lm6sEFxAPS_6g';
const client = new FusionAuthClient('Y808ZszXwPcsXvrFsBzMdmJ7N4Lv85yLkZtJcEnJc1f3GwRO56b2RLns', 'https://fusionauth.ritza.co');
const consentId = 'e5e81271-847b-467e-b172-770fa806f894';


// Route handler
router.get('/', async function(req, res, next) {
  try {
    let family = [];
    const pkce_pair = pkceChallenge();
    req.session.verifier = pkce_pair['code_verifier'];
    req.session.challenge = pkce_pair['code_challenge'];
    if (req.session.user && req.session.user.id) {
      const response = await client.retrieveFamilies(req.session.user.id);
      if (response.response.families && response.response.families.length >= 1) {
        let children = response.response.families[0].members.filter(elem => elem.role !== 'Adult');
        children = children.concat(response.response.families[0].members.filter(elem => elem.userId === req.session.user.id));
        const users = await getFamilyUsers(children);
        users.forEach(user => {
            let self = children.filter(elem => elem.userId == user.response.user.id)[0];
            user.response.user.role = self.role;
        });
        family = buildFamilyArray(users);
        const consentsResponseArray = await getUserConsentStatuses(children);
        family = updateFamilyWithConsentStatus(family, consentsResponseArray);
      }
    }
    res.render('index', {
      family: family,
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
async function getFamilyUsers(children) {
  const getUsers = children.map(elem => client.retrieveUser(elem.userId));
  const users = await Promise.all(getUsers);
  return users;
}
async function getUserConsentStatuses(children) {
  const getUserConsentStatuses = children.map(elem => client.retrieveUserConsents(elem.userId));
  const consentsResponseArray = await Promise.all(getUserConsentStatuses);
  return consentsResponseArray;
}
function buildFamilyArray(users) {
  const family = [];
  users.forEach(user => {
    family.push({"id": user.response.user.id, "email": user.response.user.email, "role": user.response.user.role});
  });
  return family;
}
function updateFamilyWithConsentStatus(family, consentsResponseArray) {
  const userIdToStatus = {};
  const userIdToUserConsentId = {};
  consentsResponseArray.forEach((oneRes) => {
    const matchingConsent = oneRes.response.userConsents.filter((userConsent) => userConsent.consent.id == consentId)[0];
    if (matchingConsent) {
      const userId = matchingConsent.userId;
      userIdToUserConsentId[userId] = matchingConsent.id;
      userIdToStatus[userId] = matchingConsent.status;
    }
  });
  return family.map((onePerson) => {
    onePerson["status"] = userIdToStatus[onePerson.id];
    onePerson["userConsentId"] = userIdToUserConsentId[onePerson.id];
    return onePerson;
  });
}

/* OAuth return from FusionAuth */
router.get('/oauth-redirect', function (req, res, next) {
    // This code stores the user in a server-side session
    client.exchangeOAuthCodeForAccessTokenUsingPKCE(req.query.code,
        clientId,
        clientSecret,
        'http://localhost:3000/oauth-redirect',
        req.session.verifier)
        .then((response) => {
            req.session.state = req.query.state;
            return client.retrieveUserUsingJWT(response.response.access_token);
        })
        .then((response) => {
            req.session.user = response.response.user;
        })
        .then((response) => {
            if (req.session.state == "confirm-child-list") {
                res.redirect(302, '/confirm-child-list');
                return
            }
            res.redirect(302, '/');

        }).catch((err) => {
        console.log("in error");
        console.error(JSON.stringify(err));
    });

});

/* Change consent */
router.post('/change-consent-status', function (req, res, next) {
    if (!req.session.user) {
        // force signin
        res.redirect(302, '/');
    }
    const userConsentId = req.body.userConsentId;
    let desiredStatus = req.body.desiredStatus;
    if (desiredStatus != 'Active') {
        desiredStatus = 'Revoked';
    }

    if (!userConsentId) {
        console.log("No userConsentId provided!");
        res.redirect(302, '/');
    }

    const patchBody = {userConsent: {status: desiredStatus}};
    client.patchUserConsent(userConsentId, patchBody)
        .then((response) => {
            res.redirect(302, '/');
        }).catch((err) => {
        console.log("in error");
        console.error(JSON.stringify(err));
    });
});

module.exports = router;
