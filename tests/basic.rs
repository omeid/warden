extern crate warden;
#[macro_use]
extern crate serde_derive;


struct Context {
    scope: String,
}

#[derive(Serialize, Deserialize)]
struct RestrictScope {
    deny_scopes: Vec<String>,
}


impl warden::Condition for RestrictScope {
    fn allow(&self, pol: warden::Policy<Context>, r: warden::Request<Context>) -> bool {
        self.deny_scopes.contains(&r.context.scope)
    }
}

#[derive(Serialize, Deserialize)]
enum Conditions {
    RestrictActions(RestrictActions),
}


// [#derive(WardenConditions)]
type Conditions = Vec<Condition<Context>>


#[test]
fn it_works() {

    assert_eq!(4, (2 + 2));
}
